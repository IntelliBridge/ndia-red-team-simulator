import { useState } from "react";
import { LabelBadge } from "./label-badge";

export interface ObservationCardProps {
  observation: {
    id: string;
    sample_index: number;
    true_label: string;
    pred_clean: string;
    pred_adv: string;
    flipped?: boolean;
    confidence_clean: number;
    confidence_adv: number;
    artifacts: Record<string, string>;
    modality?: "image" | "tabular";
    linf_norm?: number | null;
    l2_norm?: number | null;
    control_pred?: string | null;
    control_confidence?: number | null;
    center_mass_ratio_clean?: number | null;
    center_mass_ratio_adv?: number | null;
    metric_note: string;
    top_features_clean?: string[];
    top_features_adv?: string[];
    feature_values_clean?: Record<string, string | number | boolean | null>;
    feature_values_adv?: Record<string, string | number | boolean | null>;
    explanation_unavailable_reason?: string | null;
  };
  artifactUrl: (artifactId: string) => string;
}
const artifactNames = [
  "original",
  "adv",
  "perturbation",
  "control",
  "shap_clean",
  "shap_adv",
] as const;
function EvidenceImage({ src, alt }: { src: string; alt: string }) {
  const [failed, setFailed] = useState(false);
  return failed ? (
    <div
      role="img"
      aria-label={`${alt}; image unavailable`}
      className="aspect-square p-2 text-xs text-muted-foreground"
    >
      Image unavailable
    </div>
  ) : (
    <img
      className="aspect-square w-full object-contain"
      src={src}
      alt={alt}
      onError={() => setFailed(true)}
    />
  );
}
export function ObservationCard({
  observation,
  artifactUrl,
}: ObservationCardProps) {
  const tabular = observation.modality === "tabular";
  return (
    <article
      className="redsim-panel rounded-sm p-3"
      aria-label={`Evidence for sample ${observation.sample_index}`}
    >
      <header className="mb-3 flex items-center justify-between text-xs">
        <span className="font-mono">sample {observation.sample_index}</span>
        <span>
          true {observation.true_label} ·{" "}
          {observation.flipped ? "prediction flipped" : "prediction unchanged"}
        </span>
      </header>
      {tabular ? (
        <div className="grid grid-cols-2 gap-3 text-xs">
          {observation.feature_values_clean &&
          observation.feature_values_adv ? (
            <>
              <div>
                <strong>Clean feature values</strong>
                <dl>
                  {Object.entries(observation.feature_values_clean).map(
                    ([name, value]) => (
                      <div key={name}>
                        <dt>{name}</dt>
                        <dd>{String(value ?? "not recorded")}</dd>
                      </div>
                    ),
                  )}
                </dl>
              </div>
              <div>
                <strong>Adversarial feature values</strong>
                <dl>
                  {Object.entries(observation.feature_values_adv).map(
                    ([name, value]) => (
                      <div key={name}>
                        <dt>{name}</dt>
                        <dd>{String(value ?? "not recorded")}</dd>
                      </div>
                    ),
                  )}
                </dl>
              </div>
            </>
          ) : (
            <p className="col-span-2 text-muted-foreground">
              Recorded feature values are unavailable. Attribution rankings are
              not presented as input values.
            </p>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-2 md:grid-cols-3">
          {artifactNames.map((name) => (
            <figure key={name} className="overflow-hidden bg-muted">
              {observation.artifacts[name] ? (
                <EvidenceImage
                  src={artifactUrl(observation.artifacts[name])}
                  alt={`${name.replaceAll("_", " ")} recorded evidence for sample ${observation.sample_index}`}
                />
              ) : (
                <figcaption className="aspect-square p-2 text-xs text-muted-foreground">
                  {name.replaceAll("_", " ")} unavailable
                </figcaption>
              )}
              <figcaption className="p-1 text-[10px]">
                {name.replaceAll("_", " ")}
              </figcaption>
            </figure>
          ))}
        </div>
      )}
      <dl className="mt-3 grid grid-cols-2 gap-2 text-xs">
        <div>
          <dt>Clean</dt>
          <dd className="font-mono">
            {observation.pred_clean} · {observation.confidence_clean}
          </dd>
        </div>
        <div>
          <dt>Adversarial</dt>
          <dd className="font-mono">
            {observation.pred_adv} · {observation.confidence_adv}
          </dd>
        </div>
        <div>
          <dt>Norms L∞ / L2</dt>
          <dd>
            {observation.linf_norm ?? "—"} / {observation.l2_norm ?? "—"}
          </dd>
        </div>
        <div>
          <dt>Same-ε noise control</dt>
          <dd>
            {observation.control_pred == null
              ? "not recorded"
              : `${observation.control_pred} · ${observation.control_confidence ?? "—"}`}
          </dd>
        </div>
      </dl>
      {observation.explanation_unavailable_reason && (
        <p className="mt-2 text-xs text-muted-foreground">
          Explanation unavailable: {observation.explanation_unavailable_reason}
        </p>
      )}
      <p className="mt-2 text-[11px] text-muted-foreground">
        <LabelBadge variant="heuristic" /> center-mass ratio{" "}
        {observation.center_mass_ratio_clean ?? "—"} /{" "}
        {observation.center_mass_ratio_adv ?? "—"}. {observation.metric_note}
      </p>
    </article>
  );
}
