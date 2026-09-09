export function CompatibilityList({ items = [] }: { items?: string[] }) {
  return (
    <ul className="m-0 list-none space-y-0 p-0 text-sm">
      {items.map((item) => (
        <li key={item} className="border-b border-line py-2 last:border-0">
          {item}
        </li>
      ))}
    </ul>
  );
}
