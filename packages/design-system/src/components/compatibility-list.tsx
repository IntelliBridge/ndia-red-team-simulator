export function CompatibilityList({ items = [] }: { items?: string[] }) {
  return (
    <ul className="space-y-1 text-sm">
      {items.map((item) => (
        <li key={item} className="border-b border-border py-1.5">
          {item}
        </li>
      ))}
    </ul>
  );
}
