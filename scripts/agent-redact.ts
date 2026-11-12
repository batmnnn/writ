// Redaction for anything the agent scene prints or saves: no presigned query, no token,
// no account id, no long digit run, no card id.

export function redact(text: string): string {
  return text
    .replace(/(\.html)\?[^"\s\\]*/g, "$1?<presigned query removed>")
    .replace(/eyJ[\w-]+\.[\w-]+\.[\w-]+/g, "<jwt removed>")
    .replace(/\b\d{12}\b/g, "<account>")
    .replace(/\b\d{13,19}\b/g, "<digits removed>")
    .replace(/("cardId"\s*:\s*)"[^"]*"/g, '$1"<removed>"');
}
