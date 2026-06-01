import type { Meta, StoryObj } from "@storybook/react";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableFooter,
  TableHead,
  TableHeader,
  TableRow,
} from "./table";

const meta: Meta<typeof Table> = {
  component: Table,
  title: "Primitives/Table",
  tags: ["autodocs"],
};
export default meta;

type Story = StoryObj<typeof Table>;

export const Default: Story = {
  render: () => (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Finding</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>Status</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <TableRow>
          <TableCell>SQL Injection in Login Form</TableCell>
          <TableCell>critical</TableCell>
          <TableCell>open</TableCell>
        </TableRow>
        <TableRow>
          <TableCell>Reflected XSS on /search</TableCell>
          <TableCell>high</TableCell>
          <TableCell>pending_apply</TableCell>
        </TableRow>
      </TableBody>
    </Table>
  ),
};

export const WithCaptionAndFooter: Story = {
  render: () => (
    <Table>
      <TableCaption>Scan results for run rn-0007.</TableCaption>
      <TableHeader>
        <TableRow>
          <TableHead>Finding</TableHead>
          <TableHead>Severity</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <TableRow>
          <TableCell>Missing CSRF token</TableCell>
          <TableCell>medium</TableCell>
        </TableRow>
      </TableBody>
      <TableFooter>
        <TableRow>
          <TableCell>Total</TableCell>
          <TableCell>1 finding</TableCell>
        </TableRow>
      </TableFooter>
    </Table>
  ),
};
