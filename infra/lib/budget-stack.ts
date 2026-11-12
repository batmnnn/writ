import { Stack, type StackProps, Tags } from "aws-cdk-lib";
import { CfnBudget } from "aws-cdk-lib/aws-budgets";
import type { Construct } from "constructs";

export interface BudgetStackProps extends StackProps {
  alertEmail: string;
}

/** Deploy this stack first. The alerts stay on for the life of the account. */
export class BudgetStack extends Stack {
  constructor(scope: Construct, id: string, props: BudgetStackProps) {
    super(scope, id, props);
    Tags.of(this).add("project", "writ");

    const subscriber = { subscriptionType: "EMAIL", address: props.alertEmail };
    const steps = [30, 60, 90, 120, 150, 180, 210, 240, 270, 300];

    new CfnBudget(this, "Monthly", {
      budget: {
        budgetName: "writ-monthly",
        budgetType: "COST",
        timeUnit: "MONTHLY",
        budgetLimit: { amount: 300, unit: "USD" },
      },
      notificationsWithSubscribers: steps.map((amount) => ({
        notification: {
          notificationType: "ACTUAL",
          comparisonOperator: "GREATER_THAN",
          threshold: amount,
          thresholdType: "ABSOLUTE_VALUE",
        },
        subscribers: [subscriber],
      })),
    });
  }
}
