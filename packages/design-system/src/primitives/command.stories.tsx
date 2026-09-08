import type { Meta, StoryObj } from "@storybook/react";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "./command";

const meta: Meta<typeof Command> = {
  component: Command,
  title: "Primitives/Command",
  tags: ["autodocs"],
};
export default meta;

type Story = StoryObj<typeof Command>;

export const Default: Story = {
  render: () => (
    <Command className="w-96 rounded-lg border shadow-md">
      <CommandInput placeholder="Search runs, targets, findings..." />
      <CommandList>
        <CommandEmpty>No results found.</CommandEmpty>
        <CommandGroup heading="Runs">
          <CommandItem>
            Re-run last scan
            <CommandShortcut>R</CommandShortcut>
          </CommandItem>
          <CommandItem>View run rn-0007</CommandItem>
        </CommandGroup>
        <CommandSeparator />
        <CommandGroup heading="Targets">
          <CommandItem>Add target</CommandItem>
          <CommandItem>api.example.com</CommandItem>
        </CommandGroup>
      </CommandList>
    </Command>
  ),
};
