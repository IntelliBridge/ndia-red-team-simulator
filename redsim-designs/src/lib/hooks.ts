"use client"

import useSWR from "swr"
import type {
  AttackInfo,
  AuditVerifyResult,
  Campaign,
  Capabilities,
  CandidateRecommendation,
  CostRecord,
  DatasetInfo,
  DefenseInfo,
  Finding,
  Interpretation,
  LogEntry,
  Measurement,
  ModelTarget,
  MRIRecord,
  Observation,
  Project,
  Provenance,
  AuthProfile,
} from "./api-types"

const poll15 = { refreshInterval: 15_000 }

export const useCapabilities = () => useSWR<Capabilities>("/v1/ml/capabilities")
export const useAttacks = () => useSWR<AttackInfo[]>("/v1/attacks")
export const useDefenses = () => useSWR<DefenseInfo[]>("/v1/defenses")
export const useDatasets = () => useSWR<DatasetInfo[]>("/v1/datasets")
export const useModels = () => useSWR<ModelTarget[]>("/v1/models")
export const useModel = (id: string) => useSWR<ModelTarget>(id ? `/v1/models/${id}` : null)
export const useRuns = () => useSWR<Campaign[]>("/v1/runs", poll15)
export const useRun = (id: string) => useSWR<Campaign>(id ? `/v1/runs/${id}/campaign` : null)
export const useMeasurement = (id: string) => useSWR<Measurement>(id ? `/v1/runs/${id}/measurement` : null)
export const useMri = (id: string) => useSWR<MRIRecord>(id ? `/v1/runs/${id}/mri` : null)
export const useObservations = (id: string) => useSWR<Observation[]>(id ? `/v1/runs/${id}/observations` : null)
export const useInterpretation = (id: string) => useSWR<Interpretation[]>(id ? `/v1/runs/${id}/interpretation` : null)
export const useRecommendations = (id: string) => useSWR<CandidateRecommendation[]>(id ? `/v1/runs/${id}/recommendations` : null)
export const useProvenance = (id: string) => useSWR<Provenance>(id ? `/v1/runs/${id}/provenance` : null)
export const useFindings = (runId?: string) => useSWR<Finding[]>(runId ? `/v1/findings?run=${runId}` : "/v1/findings")
export const useFinding = (id: string) => useSWR<Finding>(id ? `/v1/findings/${id}` : null)
export const useProjects = () => useSWR<Project[]>("/v1/projects")
export const useAuthProfiles = () => useSWR<AuthProfile[]>("/v1/auth-profiles")
export const useAudit = () => useSWR<AuditVerifyResult>("/v1/audit/verify")
export const useLogs = () => useSWR<LogEntry[]>("/v1/logs")
export const useCost = () => useSWR<CostRecord>("/v1/orgs/org-1/cost")
