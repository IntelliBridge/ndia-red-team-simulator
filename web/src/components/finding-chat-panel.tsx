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
import * as Dialog from "@radix-ui/react-dialog";

import type { Finding } from "@/lib/api";
import { examplePrompts, type ChatTurn } from "@/lib/chat";
import { useFindingChat } from "@/hooks/useFindingChat";

export interface FindingChatPanelProps {
  finding: Finding;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function Turn({ turn, streaming }: { turn: ChatTurn; streaming: boolean }) {
  const user = turn.role === "user";
  const thinking = !user && streaming && turn.content.length === 0 && !turn.error;
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
        <p className="whitespace-pre-wrap leading-relaxed">{turn.content}</p>
      )}
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
                  and candidate recommendations. The assistant reads the finding and its campaign
                  record and nothing else.
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
                  <Turn key={turn.id} turn={turn} streaming={chat.streaming} />
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
