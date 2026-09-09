"use client"

import { useMemo, useState } from "react"
import type { Measurement, MeasurementRow } from "@/lib/api-types"

/**
 * Accuracy vs ε per attack, the control line, and the clean baseline at ε=0.
 * Inline SVG, theme-aware via currentColor / CSS vars, denominators in tooltips.
 * Highlights one attack when `highlightAttack` is set. [spec §18.3 panel 4, §5]
 */
const COLORS: Record<string, string> = {
  fgsm: "var(--primary)",
  pgd: "var(--adversarial)",
  noise_control: "var(--muted)",
}

interface Series {
  attack: string
  isControl: boolean
  points: { eps: number; acc: number; n: number; n_correct: number }[]
}

export function RobustnessCurve({
  measurement,
  highlightAttack,
}: {
  measurement: Measurement
  highlightAttack?: string
}) {
  const [hover, setHover] = useState<{ x: number; y: number; text: string } | null>(null)

  const { series, epsMax, cleanAcc } = useMemo(() => {
    const clean = measurement.rows.find((r) => r.family === "clean")
    const cleanAcc = clean && clean.n > 0 ? clean.n_correct / clean.n : null
    const byAttack = new Map<string, MeasurementRow[]>()
    for (const r of measurement.rows) {
      if (r.family === "clean" || r.attack == null || r.eps == null) continue
      const arr = byAttack.get(r.attack) ?? []
      arr.push(r)
      byAttack.set(r.attack, arr)
    }
    let epsMax = 0
    const series: Series[] = []
    for (const [attack, rows] of byAttack) {
      const sorted = [...rows].sort((a, b) => (a.eps! - b.eps!))
      const points = sorted.map((r) => {
        epsMax = Math.max(epsMax, r.eps!)
        return { eps: r.eps!, acc: r.n > 0 ? r.n_correct / r.n : 0, n: r.n, n_correct: r.n_correct }
      })
      // Anchor the clean baseline at eps=0.
      if (cleanAcc != null && clean) points.unshift({ eps: 0, acc: cleanAcc, n: clean.n, n_correct: clean.n_correct })
      series.push({ attack, isControl: rows[0].family === "control", points })
    }
    return { series, epsMax: epsMax || 0.1, cleanAcc }
  }, [measurement])

  const W = 560
  const H = 240
  const pad = { l: 44, r: 16, t: 16, b: 34 }
  const iw = W - pad.l - pad.r
  const ih = H - pad.t - pad.b
  const x = (eps: number) => pad.l + (eps / epsMax) * iw
  const y = (acc: number) => pad.t + (1 - acc) * ih

  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="Accuracy versus perturbation budget per attack">
        {/* y gridlines */}
        {[0, 0.25, 0.5, 0.75, 1].map((t) => (
          <g key={t}>
            <line x1={pad.l} x2={W - pad.r} y1={y(t)} y2={y(t)} stroke="var(--hairline)" strokeWidth={1} />
            <text x={pad.l - 6} y={y(t) + 3} textAnchor="end" className="fill-[var(--muted-2)] text-[9px]">
              {Math.round(t * 100)}%
            </text>
          </g>
        ))}
        {/* clean baseline */}
        {cleanAcc != null && (
          <line x1={pad.l} x2={W - pad.r} y1={y(cleanAcc)} y2={y(cleanAcc)} stroke="var(--robust)" strokeWidth={1} strokeDasharray="4 3" opacity={0.7} />
        )}
        {/* x ticks */}
        {[0, epsMax / 2, epsMax].map((e) => (
          <text key={e} x={x(e)} y={H - 12} textAnchor="middle" className="fill-[var(--muted-2)] text-[9px]">
            ε {e.toFixed(3)}
          </text>
        ))}
        {series.map((s) => {
          const color = s.isControl ? "var(--muted)" : COLORS[s.attack] ?? "var(--primary)"
          const dim = highlightAttack && highlightAttack !== s.attack
          const d = s.points.map((p, i) => `${i === 0 ? "M" : "L"}${x(p.eps)},${y(p.acc)}`).join(" ")
          return (
            <g key={s.attack} opacity={dim ? 0.25 : 1}>
              <path d={d} fill="none" stroke={color} strokeWidth={s.isControl ? 1.5 : 2} strokeDasharray={s.isControl ? "3 3" : undefined} />
              {s.points.map((p) => (
                <circle
                  key={p.eps}
                  cx={x(p.eps)}
                  cy={y(p.acc)}
                  r={highlightAttack === s.attack ? 4 : 3}
                  fill={color}
                  onMouseEnter={() =>
                    setHover({ x: x(p.eps), y: y(p.acc), text: `${s.attack} · ε=${p.eps} · ${p.n_correct} / ${p.n} (${(p.acc * 100).toFixed(1)}%)` })
                  }
                  onMouseLeave={() => setHover(null)}
                />
              ))}
            </g>
          )
        })}
      </svg>
      {hover && (
        <div
          className="pointer-events-none absolute z-10 -translate-x-1/2 -translate-y-full rounded border border-hairline bg-panel-2 px-2 py-1 font-mono text-[11px] text-foreground shadow"
          style={{ left: `${(hover.x / W) * 100}%`, top: `${(hover.y / H) * 100}%` }}
        >
          {hover.text}
        </div>
      )}
      <div className="mt-2 flex flex-wrap gap-3 text-[11px] text-muted">
        {series.map((s) => (
          <span key={s.attack} className="inline-flex items-center gap-1.5">
            <span className="inline-block h-2 w-2 rounded-full" style={{ background: s.isControl ? "var(--muted)" : COLORS[s.attack] ?? "var(--primary)" }} />
            {s.attack}
          </span>
        ))}
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2 w-3 border-t border-dashed border-robust" /> clean baseline
        </span>
      </div>
    </div>
  )
}
