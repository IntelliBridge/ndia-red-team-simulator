"use client";

// FindingChatPanel — the slide-out "Chat with this finding" drawer.
//
// A Radix Dialog anchored to the right edge: focus is trapped inside, Escape
// and the overlay close it, focus returns to the Chat button. The transcript
// comes from useFindingChat and the answers from the web app's own route,
// which reads the finding and campaign records with the analyst's cookie.
// The footer caveat stands whatever the model writes: an answer is a reading
// of recorded evidence, never a measurement.

import * as React from "react";
import Link from "next/link";
import * as Dialog from "@radix-ui/react-dialog";
import { RoleGated } from "@redsim/design-system";

import { mlErrorDetail, startCampaign, type Finding } from "@/lib/api";
import { buildProposalRequest, examplePrompts, parseProposal, type CampaignProposal, type ChatTurn } from "@/lib/chat";
import { useCampaign } from "@/hooks/useCampaign";
import { useFindingChat } from "@/hooks/useFindingChat";
import { useRoles } from "@/hooks/useRoles";

export interface FindingChatPanelProps {
  finding: Finding;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/**
 * A candidate campaign the assistant proposed, and the one control that acts
 * on it. The card shows the exact settings the request will carry. The Run
 * button posts them to the API's own admission (POST /v1/models/{id}/attacks),
 * which writes its attack.run audit row and admits or refuses on its own
 * checks; the refusal is shown here with its code, never rewritten. Nothing
 * is predicted about what the run will measure.
 */
function ProposalCard({
  finding,
  proposal,
  runId,
  onStarted,
}: {
  finding: Finding;
  proposal: CampaignProposal;
  runId: string | null | undefined;
  onStarted: (runId: string) => void;
}) {
  const { data: campaign, error: campaignError } = useCampaign(finding.run_id);
  const { roles } = useRoles();
  const role = roles[finding.project_id];
  const [pending, setPending] = React.useState(false);
  const [refusal, setRefusal] = React.useState<string | null>(null);

  const run = async () => {
    if (!campaign) return;
    setPending(true);
    setRefusal(null);
    try {
      // The attacks route is keyed by the Target row id the admission froze into
      // the config; the target block's id is the registry id (vehicles_cnn), which
      // the API does not resolve.
      const targetRowId = campaign.config.target_id || campaign.target.id;
      const handle = await startCampaign(targetRowId, buildProposalRequest(campaign.config, proposal));
      onStarted(handle.run_id);
    } catch (error) {
      const detail = mlErrorDetail(error);
      const message = detail.message ?? "the request was refused";
      setRefusal(detail.code ? `${detail.code}: ${message}` : message);
    } finally {
      setPending(false);
    }
  };

  return (
    <section
      aria-label="Proposed campaign"
      className="mt-3 rounded-md border border-primary/40 bg-primary/5 p-3 text-xs"
      data-testid="proposal-card"
    >
      <div className="flex items-center justify-between gap-2">
        <div className="redsim-kicker">proposed campaign · candidate, not run</div>
        {campaign ? (
          <span className="font-mono text-muted-foreground" title="target">
            {campaign.target.name}
          </span>
        ) : null}
      </div>
      <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
        <dt className="text-muted-foreground">attacks</dt>
        <dd className="font-mono">{proposal.attack_ids.join(", ")}</dd>
        <dt className="text-muted-foreground">norm</dt>
        <dd className="font-mono">{proposal.norm}</dd>
        <dt className="text-muted-foreground">eps grid</dt>
        <dd className="font-mono">
          {proposal.eps_grid.join(", ")} <span className="text-muted-foreground">(reference {proposal.reference_eps})</span>
        </dd>
        <dt className="text-muted-foreground">n samples</dt>
        <dd className="font-mono">{proposal.n_samples}</dd>
        {proposal.rationale ? (
          <>
            <dt className="text-muted-foreground">rationale</dt>
            <dd className="leading-relaxed">{proposal.rationale}</dd>
          </>
        ) : null}
      </dl>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
        <span className="text-muted-foreground">
          Approval is yours: the API admits it through its own checks and audit row.
        </span>
        {runId ? (
          <Link className="text-primary underline" href={`/runs/${runId}`}>
            Run {runId} admitted, open it
          </Link>
        ) : campaignError ? (
          <span role="alert" className="text-warning">
            The campaign record could not be read, so this proposal cannot be run from here.
          </span>
        ) : (
          <RoleGated minRole="scanner" callerRole={role}>
            <button
              type="button"
              onClick={() => void run()}
              disabled={pending || !campaign}
              className="rounded bg-primary px-3 py-1 text-xs font-medium text-primary-foreground disabled:cursor-not-allowed disabled:opacity-50"
            >
              {pending ? "Submitting…" : "Run this campaign"}
            </button>
          </RoleGated>
        )}
      </div>
      {refusal ? (
        <p role="alert" className="mt-2 text-warning">
          {refusal}
        </p>
      ) : null}
    </section>
  );
}

function Turn({
  turn,
  streaming,
  finding,
  onStarted,
}: {
  turn: ChatTurn;
  streaming: boolean;
  finding: Finding;
  onStarted: (turnId: string, runId: string) => void;
}) {
  const user = turn.role === "user";
  const thinking = !user && streaming && turn.content.length === 0 && !turn.error;
  const parsed = React.useMemo(
    () => (user ? { text: turn.content, proposal: null, invalid: null, pending: false } : parseProposal(turn.content)),
    [user, turn.content],
  );
  return (
    <li
      className={
        user
          ? "ml-8 rounded-md border border-primary/30 bg-primary/10 px-3 py-2 text-sm"
          : "mr-8 rounded-md border border-border bg-background/40 px-3 py-2 text-sm"
      }
      data-role={turn.role}
    >
      <div className="redsim-kicker mb-1">{user ? "you" : "assistant"}</div>
      {thinking ? (
        <p className="text-muted-foreground" aria-live="polite">
          Thinking…
        </p>
      ) : (
        <p className="whitespace-pre-wrap leading-relaxed">{parsed.text}</p>
      )}
      {parsed.pending ? (
        <p className="mt-2 text-xs text-muted-foreground" aria-live="polite">
          Writing a proposal…
        </p>
      ) : null}
      {parsed.proposal ? (
        <ProposalCard
          finding={finding}
          proposal={parsed.proposal}
          runId={turn.proposal_run_id}
          onStarted={(runId) => onStarted(turn.id, runId)}
        />
      ) : null}
      {parsed.invalid ? (
        <p role="alert" className="mt-2 text-xs text-warning">
          The assistant wrote a proposal this panel cannot run: {parsed.invalid}.
        </p>
      ) : null}
      {turn.error ? (
        <p role="alert" className="mt-2 text-xs text-warning">
          {turn.error}
        </p>
      ) : null}
    </li>
  );
}

export function FindingChatPanel({ finding, open, onOpenChange }: FindingChatPanelProps) {
  const chat = useFindingChat(finding.id, open);
  const [draft, setDraft] = React.useState("");
  const inputRef = React.useRef<HTMLTextAreaElement>(null);
  const logRef = React.useRef<HTMLDivElement>(null);
  const prompts = React.useMemo(() => examplePrompts(finding), [finding]);

  const unavailable = chat.status !== null && !chat.status.configured;
  const canSend = !chat.streaming && !unavailable && chat.statusError === null;

  React.useEffect(() => {
    const log = logRef.current;
    if (log) log.scrollTop = log.scrollHeight;
  }, [chat.turns]);

  const submit = (text: string) => {
    if (!canSend) return;
    setDraft("");
    void chat.send(text);
  };

  const modelLine = chat.model ?? chat.status?.model ?? null;

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="redsim-drawer-overlay fixed inset-0 z-50 bg-black/50" />
        <Dialog.Content
          className="redsim-drawer fixed inset-y-0 right-0 z-50 flex w-full max-w-md flex-col border-l border-border bg-card text-card-foreground shadow-2xl outline-none sm:max-w-lg"
          aria-describedby="finding-chat-description"
          onOpenAutoFocus={(event) => {
            event.preventDefault();
            inputRef.current?.focus();
          }}
        >
          <header className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
            <div>
              <div className="redsim-kicker">finding assistant</div>
              <Dialog.Title className="text-sm font-semibold tracking-tight">
                Chat with this finding
              </Dialog.Title>
              <Dialog.Description id="finding-chat-description" className="mt-1 font-mono text-xs text-muted-foreground">
                {finding.id}
                {modelLine ? ` · ${modelLine} via Pythia` : ""}
              </Dialog.Description>
            </div>
            <Dialog.Close
              aria-label="Close chat"
              className="rounded border border-border px-2 py-1 text-xs hover:border-primary"
            >
              Close
            </Dialog.Close>
          </header>

          <div
            ref={logRef}
            role="log"
            aria-label="Conversation"
            aria-busy={chat.streaming}
            className="flex-1 overflow-y-auto px-4 py-4"
          >
            {chat.statusError ? (
              <p role="alert" className="border border-warning/40 bg-warning/10 p-3 text-sm">
                {chat.statusError}
              </p>
            ) : unavailable ? (
              <p role="alert" className="border border-warning/40 bg-warning/10 p-3 text-sm">
                Chat is unavailable. The web server holds no Pythia gateway settings
                (PYTHIA_BASE_URL and PYTHIA_API_KEY).
              </p>
            ) : chat.turns.length === 0 ? (
              <div className="space-y-3">
                <p className="text-sm text-muted-foreground">
                  Ask about this finding&apos;s recorded measurements, observations, interpretation
                  and candidate recommendations, or ask what to run next. The assistant reads the
                  finding, its campaign record and the attack catalog and nothing else. A proposed
                  campaign runs only when you approve it.
                </p>
                <div className="redsim-kicker">example questions</div>
                <ul className="space-y-2" aria-label="Example questions">
                  {prompts.map((prompt) => (
                    <li key={prompt}>
                      <button
                        type="button"
                        onClick={() => submit(prompt)}
                        disabled={!canSend}
                        className="w-full rounded border border-border bg-background/40 px-3 py-2 text-left text-xs leading-relaxed hover:border-primary disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        {prompt}
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <ul className="space-y-3">
                {chat.turns.map((turn) => (
                  <Turn
                    key={turn.id}
                    turn={turn}
                    streaming={chat.streaming}
                    finding={finding}
                    onStarted={(turnId, runId) => chat.annotate(turnId, { proposal_run_id: runId })}
                  />
                ))}
              </ul>
            )}
          </div>

          <footer className="border-t border-border px-4 py-3">
            <p className="redsim-meta mb-2">
              Generated from the recorded finding and campaign. Not a measurement. Check the
              evidence panels before you act.
            </p>
            <form
              onSubmit={(event) => {
                event.preventDefault();
                submit(draft);
              }}
              className="space-y-2"
            >
              <label className="sr-only" htmlFor="finding-chat-input">
                Your question
              </label>
              <textarea
                id="finding-chat-input"
                ref={inputRef}
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    submit(draft);
                  }
                }}
                disabled={!canSend}
                placeholder="Ask about this finding. Enter sends, Shift+Enter adds a line."
                rows={3}
                className="redsim-input min-h-16 resize-y text-sm"
              />
              <div className="flex items-center justify-between gap-2">
                <button
                  type="button"
                  onClick={chat.clear}
                  disabled={chat.turns.length === 0}
                  className="rounded border border-border px-2 py-1 text-xs hover:border-primary disabled:cursor-not-allowed disabled:opacity-50"
                >
                  Clear
                </button>
                {chat.streaming ? (
                  <button
                    type="button"
                    onClick={chat.stop}
                    className="rounded border border-border px-3 py-1 text-xs hover:border-primary"
                  >
                    Stop
                  </button>
                ) : (
                  <button
                    type="submit"
                    disabled={!canSend || draft.trim().length === 0}
                    className="rounded bg-primary px-3 py-1 text-xs font-medium text-primary-foreground disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    Send
                  </button>
                )}
              </div>
            </form>
          </footer>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
