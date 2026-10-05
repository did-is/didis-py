"""Wire types for the DID.is public API (camelCase JSON, returned as plain ``dict``).

These are ``TypedDict`` declarations: they give editors and type checkers the response shape
without changing runtime behaviour. Fields marked ``NotRequired`` may be absent. String states
are typed as ``str`` because the server may add new states in a minor release.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, NotRequired, Optional, Tuple, TypedDict

DimensionState = Literal["ESTABLISHED", "SELF_CERTIFYING", "NOT_ESTABLISHED", "FAILED", "INDETERMINATE", "NOT_APPLICABLE"]


class TraceStage(TypedDict):
    stage: str
    label: str
    status: str
    startedUs: int
    durationUs: int
    detail: str


class Problem(TypedDict, total=False):
    type: str
    title: str
    status: int
    detail: str
    code: str
    trace: List[TraceStage]
    retryAfter: str


class Check(TypedDict):
    id: str
    label: str
    status: str
    detail: str


class EvidenceDimension(TypedDict):
    id: str
    label: str
    state: DimensionState
    statement: str
    proves: str
    doesNotProve: str


class Verdict(TypedDict):
    outcome: str
    headline: str
    statements: List[str]


class KeyEvidence(TypedDict):
    id: str
    type: str
    controller: NotRequired[str]
    controllerIsSubject: bool
    relationships: List[str]
    status: str
    curve: NotRequired[str]
    keySizeBits: NotRequired[int]
    jwkThumbprint: NotRequired[str]
    multikey: NotRequired[str]
    jwk: NotRequired[Dict[str, Any]]
    detail: str


class DomainBindingEvidence(TypedDict):
    status: str
    origin: str
    configurationUrl: str
    linkedDids: List[str]
    credentials: List[Dict[str, Any]]
    detail: str


class Evidence(TypedDict):
    source: Dict[str, Any]
    document: Dict[str, Any]
    keys: List[KeyEvidence]
    services: List[Dict[str, Any]]
    domainBinding: NotRequired[DomainBindingEvidence]
    tls: NotRequired[Dict[str, Any]]
    history: NotRequired[Dict[str, Any]]


class GraphNode(TypedDict):
    id: str
    kind: str
    label: str
    sublabel: NotRequired[str]
    state: str
    layer: int
    digest: NotRequired[str]
    facts: List[Tuple[str, str]]


# ``from`` is a Python keyword, so this TypedDict uses the functional form.
GraphEdge = TypedDict("GraphEdge", {"id": str, "from": str, "to": str, "relation": str, "state": str})


class Graph(TypedDict):
    nodes: List[GraphNode]
    edges: List[GraphEdge]


class EnrichedResolution(TypedDict):
    did: str
    method: str
    didDocument: Optional[Dict[str, Any]]
    didResolutionMetadata: Dict[str, Any]
    didDocumentMetadata: Dict[str, Any]
    verdict: Verdict
    dimensions: List[EvidenceDimension]
    evidence: Evidence
    graph: Graph
    trace: List[TraceStage]
    limitations: List[str]
    resolver: Dict[str, str]
    observedAt: str
    cached: bool


ResolutionResult = TypedDict(
    "ResolutionResult",
    {"@context": str, "didDocument": Optional[Dict[str, Any]], "didResolutionMetadata": Dict[str, Any], "didDocumentMetadata": Dict[str, Any]},
)

DereferencingResult = TypedDict(
    "DereferencingResult",
    {"@context": str, "dereferencingMetadata": Dict[str, Any], "contentStream": Any, "contentMetadata": Dict[str, Any]},
)


class HealthStatus(TypedDict):
    status: str
    name: str
    version: str
    time: str
    supportedMethods: List[str]
    standards: Dict[str, Any]
    monitoring: NotRequired[bool]
    rateLimited: NotRequired[bool]


class ObservationRecord(TypedDict):
    id: int
    did: str
    documentHash: str
    observedAt: str
    lastSeenAt: str
    seenCount: int
    latencyMs: int
    resolverVersion: str
    domainBindingStatus: str
    summary: Optional[Dict[str, Any]]


class HistoryResponse(TypedDict):
    did: str
    count: int
    history: List[ObservationRecord]
    note: str


class RelationshipChange(TypedDict):
    relationship: str
    added: List[str]
    removed: List[str]


class SemanticDiff(TypedDict):
    did: str
    fromHash: str
    toHash: str
    fromObservedAt: str
    toObservedAt: str
    identical: bool
    keysAdded: List[str]
    keysRemoved: List[str]
    keysRotated: List[str]
    relationshipsChanged: List[RelationshipChange]
    servicesAdded: List[str]
    servicesRemoved: List[str]
    servicesChanged: List[str]
    controllerChanged: bool
    alsoKnownAsChanged: bool
    contextsChanged: bool
    domainBindingFrom: str
    domainBindingTo: str
    domainBindingChanged: bool
    changedMembers: List[str]
    summary: List[str]
    fromDocument: Any
    toDocument: Any


class GraphResponse(TypedDict):
    did: str
    observedAt: str
    verdict: Verdict
    nodes: List[GraphNode]
    edges: List[GraphEdge]


class CredentialVerification(TypedDict):
    status: str
    headline: str
    format: str
    dataModel: str
    id: NotRequired[str]
    issuer: NotRequired[str]
    issuerName: NotRequired[str]
    subject: NotRequired[str]
    types: List[str]
    validFrom: NotRequired[str]
    validUntil: NotRequired[str]
    checks: List[Check]
    proof: NotRequired[Dict[str, Any]]
    statusList: List[Dict[str, Any]]
    issuerResolution: NotRequired[Dict[str, Any]]
    claims: Any
    credential: Any
    limitations: List[str]
    valid: bool
    errors: List[str]


class PolicyRules(TypedDict, total=False):
    didResolution: Literal["required", "optional"]
    allowedMethods: List[str]
    allowedCurves: List[str]
    allowedKeySuites: List[str]
    minKeyBits: int
    requireKeyRelationship: str
    domainBinding: Literal["required", "optional"]
    tlsMinDaysRemaining: int
    verifiableHistory: Literal["required"]
    maxCacheAgeSeconds: int
    credentialStatus: Literal["active"]
    credentialIssuerMustBeSubject: bool


class Policy(TypedDict):
    name: NotRequired[str]
    rules: PolicyRules


class PolicyRuleEvaluation(TypedDict):
    rule: str
    status: str
    message: str
    expected: NotRequired[Any]
    observedValue: NotRequired[Any]


class PolicyEvaluation(TypedDict):
    did: str
    policyName: NotRequired[str]
    status: Literal["PASS", "FAIL", "INDETERMINATE", "NOT_APPLICABLE"]
    headline: str
    rulesEvaluated: int
    rulesPassed: int
    evaluations: List[PolicyRuleEvaluation]
    evaluatedAt: str


class PolicyResponse(TypedDict):
    evaluation: PolicyEvaluation
    credential: Optional[CredentialVerification]
    resolution: Optional[Dict[str, Any]]


class ToolEvidence(TypedDict):
    name: str
    title: NotRequired[str]
    description: str
    definitionSha256: str
    schemaSha256: str
    parameters: List[str]
    annotations: Any
    declaredClass: NotRequired[str]
    heuristicClass: str
    riskSignals: List[str]
    drift: str
    inputSchema: Any


class McpInspection(TypedDict):
    endpoint: str
    status: str
    mode: str
    negotiatedVersion: NotRequired[str]
    supportedVersions: List[str]
    serverInfo: Optional[Dict[str, Any]]
    capabilities: Any
    instructions: NotRequired[str]
    tools: List[ToolEvidence]
    inventoryHash: str
    jcsProfile: NotRequired[str]
    classCounts: Dict[str, int]
    drift: Dict[str, Any]
    auth: NotRequired[Dict[str, Any]]
    transcript: List[Dict[str, Any]]
    checks: List[Check]
    headline: str
    tls: NotRequired[Dict[str, Any]]
    limitations: List[str]


class A2aInspection(TypedDict):
    cardUrl: str
    httpStatus: int
    cardSha256: str
    canonicalSha256: str
    jcsProfile: NotRequired[str]
    specVersion: str
    name: str
    description: str
    version: NotRequired[str]
    provider: NotRequired[Dict[str, Any]]
    documentationUrl: NotRequired[str]
    interfaces: List[Dict[str, Any]]
    capabilities: Optional[Dict[str, Any]]
    securitySchemes: List[Dict[str, Any]]
    skills: List[Dict[str, Any]]
    signatures: List[Dict[str, Any]]
    checks: List[Check]
    headline: str
    card: Any
    tls: NotRequired[Dict[str, Any]]
    limitations: List[str]


class DelegationLink(TypedDict):
    index: int
    issuer: str
    audience: str
    capabilities: List[str]
    notBefore: NotRequired[str]
    expires: NotRequired[str]
    jti: NotRequired[str]
    kid: NotRequired[str]
    alg: NotRequired[str]
    digest: str
    signatureValid: bool
    status: str
    issuerHeadline: NotRequired[str]
    checks: List[Check]


class DelegationChainResult(TypedDict):
    status: str
    headline: str
    format: str
    root: NotRequired[str]
    leaf: NotRequired[str]
    effectiveCapabilities: List[str]
    notAfter: NotRequired[str]
    trustedRoot: NotRequired[bool]
    links: List[DelegationLink]
    checks: List[Check]
    limitations: List[str]


class DelegationVerification(TypedDict):
    result: DelegationChainResult
    registered: bool


class ToolAuthorization(TypedDict):
    agent: str
    tool: str
    decision: Literal["ALLOW", "DENY"]
    authorized: bool
    reason: str
    matchedCapability: NotRequired[str]
    root: NotRequired[str]
    expires: NotRequired[str]


class AuthorizationResponse(TypedDict):
    authorization: ToolAuthorization
    chain: DelegationChainResult


class FastVerifyDidResult(TypedDict):
    did: str
    resolved: bool
    outcome: str
    headline: str
    statements: List[str]
    dimensions: List[Dict[str, str]]
    keys: List[Dict[str, Any]]
    domainBinding: Optional[str]
    documentSha256: NotRequired[str]
    observedAt: str
    cached: bool


class FastVerifyJwsResult(TypedDict):
    status: Literal["VALID", "INVALID", "INDETERMINATE", "UNSUPPORTED", "MALFORMED"]
    valid: bool
    headline: str
    alg: NotRequired[str]
    kid: NotRequired[str]
    typ: NotRequired[str]
    payload: NotRequired[Any]
    signingInputSha256: NotRequired[str]
    signer: NotRequired[str]
    relationship: NotRequired[str]
