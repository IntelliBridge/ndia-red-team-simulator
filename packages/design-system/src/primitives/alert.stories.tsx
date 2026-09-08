import type { Meta, StoryObj } from "@storybook/react";
import { Alert, AlertDescription, AlertTitle } from "./alert";

const meta: Meta<typeof Alert> = {
  component: Alert,
  title: "Primitives/Alert",
  tags: ["autodocs"],
};
export default meta;

type Story = StoryObj<typeof Alert>;

export const Default: Story = {
  render: () => (
    <Alert className="w-96">
      <AlertTitle>Scan complete</AlertTitle>
      <AlertDescription>
        Run rn-0007 finished with 3 findings.
      </AlertDescription>
    </Alert>
  ),
};

export const Destructive: Story = {
  render: () => (
    <Alert variant="destructive" className="w-96">
      <AlertTitle>Remediation failed</AlertTitle>
      <AlertDescription>
        The proposed patch could not be applied to the target branch.
      </AlertDescription>
    </Alert>
  ),
};
