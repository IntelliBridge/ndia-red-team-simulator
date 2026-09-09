// DimensionBars — the MRI subscores as five ruled rows.
//
// Each row is the dimension key, a hairline track and a bone fill, and the
// value in tabular figures. Bone is the adversarial data mark everywhere in
// the interface, so the fill reads as "measured under attack" without a
// legend. The key is the contract label (S_acc, S_asr, ...) and is shown as
// written; the caption beside it is the plain reading of the same key.

const READINGS: Record<string, string> = {
  S_acc: "clean accuracy",
  S_asr: "attack success",
  S_eps: "epsilon to flip",
  S_conf: "confidence shift",
  S_expl: "explanation stability",
};

export function DimensionBars({ values }: { values: Record<string, number> }) {
  return (
    <ul className="m-0 list-none space-y-2 p-0">
      {Object.entries(values).map(([key, value]) => {
        const width = Math.max(0, Math.min(100, value));
        return (
          <li key={key} className="grid grid-cols-[6.5rem_1fr_3rem] items-center gap-3 text-xs">
            <span className="flex flex-col leading-tight">
              <span className="font-mono text-[11px] text-ink-1">{key}</span>
              {READINGS[key] && (
                <span className="text-[11px] text-ink-3">{READINGS[key]}</span>
              )}
            </span>
            <span className="relative block h-px w-full bg-line-strong" aria-hidden="true">
              <span
                className="absolute left-0 top-1/2 block h-[3px] -translate-y-1/2 bg-data-adv transition-[width] duration-300"
                style={{ width: `${width}%` }}
              />
            </span>
            <span className="text-right tabular-nums text-ink-1">{value.toFixed(1)}</span>
          </li>
        );
      })}
    </ul>
  );
}
