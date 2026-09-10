"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import {
  describeChatError,
  fetchChatStatus,
  loadConversation,
  newTurnId,
  saveConversation,
  streamFindingChat,
  type ChatStatus,
  type ChatTurn,
} from "@/lib/chat";

export type FindingChatState = {
  turns: ChatTurn[];
  /** `null` until the status call answers. */
  status: ChatStatus | null;
  statusError: string | null;
  streaming: boolean;
  /** The model the last answer came from, as the route reported it. */
  model: string | null;
  send: (text: string) => Promise<void>;
  stop: () => void;
  clear: () => void;
};

/**
 * One conversation about one finding.
 *
 * The transcript lives in the browser (sessionStorage, per finding) and is
 * sent whole on every turn, so the server keeps nothing. `enabled` gates the
 * status call to the moment the panel opens.
 */
export function useFindingChat(findingId: string, enabled: boolean): FindingChatState {
  const [turns, setTurns] = useState<ChatTurn[]>(() => loadConversation(findingId));
  const [status, setStatus] = useState<ChatStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [streaming, setStreaming] = useState(false);
  const [model, setModel] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    setTurns(loadConversation(findingId));
  }, [findingId]);

  useEffect(() => {
    if (!enabled || status !== null) return;
    let cancelled = false;
    fetchChatStatus()
      .then((value) => {
        if (!cancelled) setStatus(value);
      })
      .catch((cause: unknown) => {
        if (!cancelled) setStatusError(describeChatError(cause));
      });
    return () => {
      cancelled = true;
    };
  }, [enabled, status]);

  useEffect(() => {
    if (!streaming) saveConversation(findingId, turns);
  }, [findingId, turns, streaming]);

  const stop = useCallback(() => {
    abortRef.current?.abort();
  }, []);

  const clear = useCallback(() => {
    abortRef.current?.abort();
    setTurns([]);
    saveConversation(findingId, []);
  }, [findingId]);

  const send = useCallback(
    async (text: string) => {
      const content = text.trim();
      if (!content || streaming) return;
      const user: ChatTurn = { id: newTurnId(), role: "user", content };
      const assistant: ChatTurn = { id: newTurnId(), role: "assistant", content: "" };
      const history = [...turns.filter((turn) => turn.content.length > 0 && !turn.error), user];
      setTurns([...history, assistant]);
      setStreaming(true);
      const controller = new AbortController();
      abortRef.current = controller;
      const patch = (update: Partial<ChatTurn>) =>
        setTurns((current) =>
          current.map((turn) => (turn.id === assistant.id ? { ...turn, ...update } : turn)),
        );
      try {
        for await (const event of streamFindingChat(
          findingId,
          history.map(({ role, content: turnText }) => ({ role, content: turnText })),
          controller.signal,
        )) {
          if (event.type === "meta") setModel(event.model);
          else if (event.type === "delta")
            setTurns((current) =>
              current.map((turn) =>
                turn.id === assistant.id ? { ...turn, content: turn.content + event.text } : turn,
              ),
            );
          else if (event.type === "error") patch({ error: event.message });
        }
      } catch (cause) {
        patch({ error: describeChatError(cause) });
      } finally {
        abortRef.current = null;
        setStreaming(false);
      }
    },
    [findingId, streaming, turns],
  );

  return { turns, status, statusError, streaming, model, send, stop, clear };
}
