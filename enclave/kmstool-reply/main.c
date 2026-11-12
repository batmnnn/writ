/*
 * kmstool_reply: KMS Decrypt with a Nitro attestation, printing the reply KeyId.
 *
 * kmstool_enclave_cli (aws-nitro-enclaves-sdk-c v0.4.6) prints only "PLAINTEXT: <base64>". The
 * SDK parses the KeyId of the Decrypt response and then drops it, so the enclave cannot check which
 * key KMS actually used. This helper does the same request with the same public SDK calls and keeps
 * the KeyId. On success stdout is exactly two lines:
 *
 *   PLAINTEXT: <base64>
 *   KEYID: <key ARN from the KMS response>
 *
 * Arguments match `kmstool_enclave_cli decrypt` so src/host/kms-unseal.ts builds one argv for both.
 * --encryption-algorithm is not accepted: the sealed key is symmetric, so it is always
 * SYMMETRIC_DEFAULT.
 *
 * Refusals, each with exit code 1 and nothing on stdout:
 *   --key-id that is not a full KMS key ARN (an alias can be re-pointed at another key);
 *   a reply KeyId that is not byte for byte the requested ARN.
 *
 * Built against the SDK at commit f2dbc3fb1ab9b4496ff8ebc077d24e5f24265923 (tag v0.4.6), the same
 * commit enclave/Dockerfile pins for kmstool_enclave_cli. Not built or run on a Mac.
 *
 * stderr carries short fixed messages only. Plaintext, credentials and ciphertext never go to it.
 */

#include <aws/nitro_enclaves/attestation.h>
#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>
#include <aws/nitro_enclaves/rest.h>

#include <aws/auth/credentials.h>
#include <aws/common/byte_buf.h>
#include <aws/common/encoding.h>
#include <aws/common/string.h>
#include <aws/http/request_response.h>
#include <aws/io/socket.h>
#include <aws/io/stream.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Declared in include/aws/nitro_enclaves/internal/cms.h at the pinned commit. The SDK exports the
 * symbols but does not install internal headers, so the prototypes are repeated here unchanged.
 */
AWS_EXTERN_C_BEGIN
AWS_NITRO_ENCLAVES_API
int aws_cms_parse_enveloped_data(
    struct aws_byte_buf *in_ber,
    struct aws_byte_buf *cipherkey,
    struct aws_byte_buf *iv,
    struct aws_byte_buf *ciphertext);
AWS_NITRO_ENCLAVES_API
int aws_cms_cipher_decrypt(
    struct aws_byte_buf *ciphertext,
    struct aws_byte_buf *key,
    struct aws_byte_buf *iv,
    struct aws_byte_buf *plaintext);
AWS_EXTERN_C_END

#define PARENT_CID "3"
#define MAX_ARG_LEN 8192

struct args {
    const char *region;
    const char *proxy_port;
    const char *access_key_id;
    const char *secret_access_key;
    const char *session_token;
    const char *ciphertext_b64;
    const char *key_id;
};

static int refuse(const char *msg) {
    fprintf(stderr, "kmstool_reply: %s\n", msg);
    return 1;
}

static int is_key_arn(const char *s) {
    /* arn:aws:kms:<region>:<12 digit account>:key/<uuid>. No alias, no bare key id. */
    if (strstr(s, "alias/") != NULL) {
        return 0;
    }
    const char *prefix = "arn:aws:kms:";
    if (strncmp(s, prefix, strlen(prefix)) != 0) {
        return 0;
    }
    const char *p = s + strlen(prefix);
    const char *colon = strchr(p, ':');
    if (colon == NULL || colon == p) {
        return 0;
    }
    for (const char *c = p; c < colon; c++) {
        if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '-')) {
            return 0;
        }
    }
    p = colon + 1;
    for (int i = 0; i < 12; i++, p++) {
        if (*p < '0' || *p > '9') {
            return 0;
        }
    }
    if (strncmp(p, ":key/", 5) != 0) {
        return 0;
    }
    p += 5;
    /* 8-4-4-4-12 lowercase hex. */
    static const int groups[5] = {8, 4, 4, 4, 12};
    for (int g = 0; g < 5; g++) {
        for (int i = 0; i < groups[g]; i++, p++) {
            if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) {
                return 0;
            }
        }
        if (g < 4) {
            if (*p != '-') {
                return 0;
            }
            p++;
        }
    }
    return *p == '\0';
}

static int parse_args(int argc, char **argv, struct args *a) {
    memset(a, 0, sizeof(*a));
    if (argc < 2 || strcmp(argv[1], "decrypt") != 0) {
        return refuse("usage: kmstool_reply decrypt --region R --proxy-port P --aws-access-key-id I "
                      "--aws-secret-access-key S --aws-session-token T --ciphertext B64 --key-id ARN");
    }
    for (int i = 2; i < argc; i += 2) {
        const char *flag = argv[i];
        if (i + 1 >= argc) {
            return refuse("an option has no value");
        }
        const char *value = argv[i + 1];
        if (value[0] == '\0' || strlen(value) > MAX_ARG_LEN) {
            return refuse("an option value is empty or too long");
        }
        const char **slot = NULL;
        if (strcmp(flag, "--region") == 0) {
            slot = &a->region;
        } else if (strcmp(flag, "--proxy-port") == 0) {
            slot = &a->proxy_port;
        } else if (strcmp(flag, "--aws-access-key-id") == 0) {
            slot = &a->access_key_id;
        } else if (strcmp(flag, "--aws-secret-access-key") == 0) {
            slot = &a->secret_access_key;
        } else if (strcmp(flag, "--aws-session-token") == 0) {
            slot = &a->session_token;
        } else if (strcmp(flag, "--ciphertext") == 0) {
            slot = &a->ciphertext_b64;
        } else if (strcmp(flag, "--key-id") == 0) {
            slot = &a->key_id;
        } else {
            return refuse("unknown option");
        }
        if (*slot != NULL) {
            return refuse("an option was given twice");
        }
        *slot = value;
    }
    if (!a->region || !a->proxy_port || !a->access_key_id || !a->secret_access_key || !a->session_token ||
        !a->ciphertext_b64 || !a->key_id) {
        return refuse("every option is required");
    }
    if (!is_key_arn(a->key_id)) {
        return refuse("--key-id must be a full KMS key ARN, never an alias");
    }
    char *end = NULL;
    long port = strtol(a->proxy_port, &end, 10);
    if (end == NULL || *end != '\0' || port < 1 || port > 65535) {
        return refuse("--proxy-port is not a valid port");
    }
    return 0;
}

static int b64_decode(struct aws_allocator *alloc, const char *in, struct aws_byte_buf *out) {
    struct aws_byte_cursor cur = aws_byte_cursor_from_c_str(in);
    size_t len = 0;
    if (aws_base64_compute_decoded_len(&cur, &len) != AWS_OP_SUCCESS || len == 0) {
        return AWS_OP_ERR;
    }
    if (aws_byte_buf_init(out, alloc, len) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }
    return aws_base64_decode(&cur, out);
}

static int b64_encode(struct aws_allocator *alloc, const struct aws_byte_buf *in, struct aws_byte_buf *out) {
    struct aws_byte_cursor cur = aws_byte_cursor_from_buf(in);
    size_t len = 0;
    if (aws_base64_compute_encoded_len(in->len, &len) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }
    if (aws_byte_buf_init(out, alloc, len + 1) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }
    if (aws_base64_encode(&cur, out) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }
    return aws_byte_buf_append_null_terminator(out);
}

/* POST TrentService.Decrypt and return the raw JSON body. Same calls the SDK makes internally. */
static struct aws_string *kms_call_decrypt(
    struct aws_nitro_enclaves_kms_client *client,
    const struct aws_string *request_json,
    int *http_status) {
    *http_status = 0;
    struct aws_nitro_enclaves_rest_response *rest = aws_nitro_enclaves_rest_client_request_blocking(
        client->rest_client,
        aws_http_method_post,
        aws_byte_cursor_from_c_str("/"),
        aws_byte_cursor_from_c_str("TrentService.Decrypt"),
        aws_byte_cursor_from_string(request_json));
    if (rest == NULL) {
        return NULL;
    }
    struct aws_string *body = NULL;
    struct aws_input_stream *stream = aws_http_message_get_body_stream(rest->response);
    int64_t length = 0;
    if (stream != NULL && aws_input_stream_get_length(stream, &length) == AWS_OP_SUCCESS && length > 0 &&
        length < (1 << 20)) {
        struct aws_byte_buf data;
        if (aws_byte_buf_init(&data, client->allocator, (size_t)length) == AWS_OP_SUCCESS) {
            if (aws_input_stream_read(stream, &data) == AWS_OP_SUCCESS && data.len == (size_t)length) {
                body = aws_string_new_from_array(client->allocator, data.buffer, data.len);
            }
            aws_byte_buf_clean_up_secure(&data);
        }
    }
    aws_http_message_get_response_status(rest->response, http_status);
    aws_nitro_enclaves_rest_response_destroy(rest);
    return body;
}

/* CiphertextForRecipient is CMS EnvelopedData for our attestation RSA key. Same steps as the SDK. */
static int open_envelope(
    struct aws_allocator *alloc,
    struct aws_rsa_keypair *keypair,
    struct aws_byte_buf *envelope,
    struct aws_byte_buf *plaintext) {
    struct aws_byte_buf wrapped_key, key, iv, body;
    AWS_ZERO_STRUCT(wrapped_key);
    AWS_ZERO_STRUCT(key);
    AWS_ZERO_STRUCT(iv);
    AWS_ZERO_STRUCT(body);
    int rc = aws_cms_parse_enveloped_data(envelope, &wrapped_key, &iv, &body);
    if (rc == AWS_OP_SUCCESS) {
        rc = aws_attestation_rsa_decrypt(alloc, keypair, &wrapped_key, &key);
    }
    if (rc == AWS_OP_SUCCESS) {
        rc = aws_cms_cipher_decrypt(&body, &key, &iv, plaintext);
    }
    aws_byte_buf_clean_up_secure(&wrapped_key);
    aws_byte_buf_clean_up_secure(&key);
    aws_byte_buf_clean_up(&iv);
    aws_byte_buf_clean_up(&body);
    return rc;
}

static int run(struct aws_allocator *alloc, const struct args *a) {
    int status = 1;
    struct aws_credentials *creds = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;
    struct aws_string *region = NULL;
    struct aws_kms_decrypt_request *req = NULL;
    struct aws_string *req_json = NULL;
    struct aws_string *resp_json = NULL;
    struct aws_kms_decrypt_response *resp = NULL;
    struct aws_byte_buf plaintext, plaintext_b64;
    AWS_ZERO_STRUCT(plaintext);
    AWS_ZERO_STRUCT(plaintext_b64);

    region = aws_string_new_from_c_str(alloc, a->region);
    creds = aws_credentials_new(
        alloc,
        aws_byte_cursor_from_c_str(a->access_key_id),
        aws_byte_cursor_from_c_str(a->secret_access_key),
        aws_byte_cursor_from_c_str(a->session_token),
        UINT64_MAX);
    if (region == NULL || creds == NULL) {
        refuse("could not set up credentials");
        goto done;
    }

    struct aws_socket_endpoint endpoint;
    AWS_ZERO_STRUCT(endpoint);
    snprintf(endpoint.address, sizeof(endpoint.address), "%s", PARENT_CID);
    endpoint.port = (uint32_t)strtol(a->proxy_port, NULL, 10);
    struct aws_nitro_enclaves_kms_client_configuration config = {
        .allocator = alloc,
        .endpoint = &endpoint,
        .domain = AWS_SOCKET_VSOCK,
        .region = region,
        .credentials = creds,
    };
    client = aws_nitro_enclaves_kms_client_new(&config);
    if (client == NULL) {
        refuse("could not create the KMS client");
        goto done;
    }

    req = aws_kms_decrypt_request_new(alloc);
    if (req == NULL) {
        refuse("out of memory");
        goto done;
    }
    if (b64_decode(alloc, a->ciphertext_b64, &req->ciphertext_blob) != AWS_OP_SUCCESS) {
        refuse("ciphertext is not base64");
        goto done;
    }
    req->key_id = aws_string_new_from_c_str(alloc, a->key_id);
    req->encryption_algorithm = AWS_EA_SYMMETRIC_DEFAULT;
    req->recipient = aws_recipient_new(alloc);
    if (req->key_id == NULL || req->recipient == NULL) {
        refuse("out of memory");
        goto done;
    }
    /* NSM attestation document over the client's fresh RSA public key. Fails outside an enclave. */
    if (aws_attestation_request(alloc, client->keypair, &req->recipient->attestation_document) != AWS_OP_SUCCESS) {
        refuse("could not get an attestation document from NSM");
        goto done;
    }
    req->recipient->key_encryption_algorithm = AWS_KEA_RSAES_OAEP_SHA_256;

    req_json = aws_kms_decrypt_request_to_json(req);
    if (req_json == NULL) {
        refuse("could not encode the request");
        goto done;
    }
    int http_status = 0;
    resp_json = kms_call_decrypt(client, req_json, &http_status);
    if (resp_json == NULL || http_status != 200) {
        fprintf(stderr, "kmstool_reply: KMS Decrypt failed (HTTP %d)\n", http_status);
        goto done;
    }
    resp = aws_kms_decrypt_response_from_json(alloc, resp_json);
    if (resp == NULL || !aws_string_is_valid(resp->key_id)) {
        refuse("KMS reply has no KeyId");
        goto done;
    }
    /* Checked before the envelope is opened. The caller checks it again against the baked ARN. */
    if (!aws_string_eq(resp->key_id, req->key_id)) {
        refuse("KMS answered for a different key");
        goto done;
    }
    if (resp->plaintext.len != 0 || resp->ciphertext_for_recipient.len == 0) {
        refuse("KMS reply is not sealed to the attestation key");
        goto done;
    }
    if (open_envelope(alloc, client->keypair, &resp->ciphertext_for_recipient, &plaintext) != AWS_OP_SUCCESS ||
        plaintext.len == 0) {
        refuse("could not open the KMS reply");
        goto done;
    }
    if (b64_encode(alloc, &plaintext, &plaintext_b64) != AWS_OP_SUCCESS) {
        refuse("could not encode the plaintext");
        goto done;
    }

    if (fprintf(stdout, "PLAINTEXT: %s\nKEYID: %s\n", (const char *)plaintext_b64.buffer, aws_string_c_str(resp->key_id)) <
            0 ||
        fflush(stdout) != 0) {
        goto done;
    }
    status = 0;

done:
    aws_byte_buf_clean_up_secure(&plaintext);
    aws_byte_buf_clean_up_secure(&plaintext_b64);
    aws_kms_decrypt_response_destroy(resp);
    aws_string_destroy(resp_json);
    aws_string_destroy(req_json);
    aws_kms_decrypt_request_destroy(req);
    if (client != NULL) {
        aws_nitro_enclaves_kms_client_destroy(client);
    }
    if (creds != NULL) {
        aws_credentials_release(creds);
    }
    aws_string_destroy(region);
    return status;
}

int main(int argc, char **argv) {
    struct args a;
    if (parse_args(argc, argv, &a) != 0) {
        return 1;
    }
    aws_nitro_enclaves_library_init(NULL);
    if (aws_nitro_enclaves_library_seed_entropy(1024) != AWS_OP_SUCCESS) {
        aws_nitro_enclaves_library_clean_up();
        return refuse("could not seed entropy");
    }
    int status = run(aws_nitro_enclaves_get_allocator(), &a);
    aws_nitro_enclaves_library_clean_up();
    return status;
}
