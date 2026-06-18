import type { Meta, StoryObj } from "@storybook/react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "./alert-dialog";

const meta: Meta<typeof AlertDialog> = {
  component: AlertDialog,
  title: "Primitives/AlertDialog",
  tags: ["autodocs"],
};
export default meta;

type Story = StoryObj<typeof AlertDialog>;

export const CancelRun: Story = {
  render: () => (
    <AlertDialog>
      <AlertDialogTrigger className="rounded-md border px-4 py-2 text-sm">
        Cancel run
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Cancel run rn-0007?</AlertDialogTitle>
          <AlertDialogDescription>
            This stops the active scan immediately. Findings collected so far
            are preserved, but in-flight stages will be abandoned.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Keep running</AlertDialogCancel>
          <AlertDialogAction variant="destructive">
            Cancel run
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  ),
};

export const DeleteTarget: Story = {
  render: () => (
    <AlertDialog>
      <AlertDialogTrigger className="rounded-md border px-4 py-2 text-sm">
        Delete target
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete this target?</AlertDialogTitle>
          <AlertDialogDescription>
            This permanently removes the target and its scan history. This
            action cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction variant="destructive">Delete</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  ),
};
