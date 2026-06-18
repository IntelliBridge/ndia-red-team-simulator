import type { Meta, StoryObj } from "@storybook/react";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "./card";

const meta: Meta<typeof Card> = {
  component: Card,
  title: "Primitives/Card",
  tags: ["autodocs"],
};
export default meta;

type Story = StoryObj<typeof Card>;

export const Default: Story = {
  render: () => (
    <Card className="w-80">
      <CardHeader>
        <CardTitle>Scan Summary</CardTitle>
        <CardDescription>Latest results for run rn-0007.</CardDescription>
      </CardHeader>
      <CardContent>3 findings across 2 targets.</CardContent>
    </Card>
  ),
};

export const WithActionAndFooter: Story = {
  render: () => (
    <Card className="w-80">
      <CardHeader>
        <CardTitle>SQL Injection</CardTitle>
        <CardDescription>vuln-0001</CardDescription>
        <CardAction>critical</CardAction>
      </CardHeader>
      <CardContent>
        User-supplied email flows directly into an unparameterised query.
      </CardContent>
      <CardFooter>Detected 2 minutes ago.</CardFooter>
    </Card>
  ),
};
