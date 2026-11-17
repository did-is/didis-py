"""Wire types for the DID.is public API (camelCase JSON, returned as plain ``dict``).

These are ``TypedDict`` declarations: they give editors and type checkers the response shape
without changing runtime behaviour. Fields marked ``NotRequired`` may be absent. String states
are typed as ``str`` because the server may add new states in a minor release.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, NotRequired, Optional, TypedDict, Union

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
    materialProperty: NotRequired[str]
    multicodec: NotRequired[Dict[str, Any]]
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


class LinkedAccountEvidence(TypedDict):
    """One ``alsoKnownAs`` value checked for a reciprocal link back to the DID."""

    value: str
    kind: str  # WEB_ORIGIN | WEB_PAGE | SAME_ORIGIN | DID | OTHER
    origin: NotRequired[str]
    status: str  # CONFIRMED | NOT_CONFIRMED | FAILED | UNSUPPORTED | UNREACHABLE | NOT_CHECKABLE
    configurationStatus: NotRequired[str]
    configurationSha256: NotRequired[str]
    detail: str


class Evidence(TypedDict):
    source: Dict[str, Any]
    document: Dict[str, Any]
    keys: List[KeyEvidence]
    services: List[Dict[str, Any]]
    domainBinding: NotRequired[DomainBindingEvidence]
    linkedAccounts: NotRequired[List[LinkedAccountEvidence]]
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
    # JSON arrays (each pair contains exactly two strings), not Python tuples.
    facts: List[List[str]]


class GraphProvenance(TypedDict):
    """DID.is-native relation-specific evidence, not independent proof or a new verdict."""
    profile: str
    method: str
    evidenceRefs: List[str]
    observedAt: str
    verifier: Dict[str, str]
    sourceUri: NotRequired[str]
    hashes: List[List[str]]
    validFrom: NotRequired[str]
    validUntil: NotRequired[str]
    limitations: List[str]


class GraphCoverage(TypedDict):
    scope: str
    keysShown: int
    keysTotal: int
    servicesShown: int
    servicesTotal: int
    aliasesShown: int
    aliasesTotal: int
    controllersShown: int
    controllersTotal: int
    truncated: bool
    note: str


class GraphObservation(TypedDict):
    id: str
    did: str
    observedAt: str
    snapshotHash: str
    nodeCount: int
    edgeCount: int
    resolverVersion: str


# ``from`` is a Python keyword, so this TypedDict uses the functional form.
GraphEdge = TypedDict("GraphEdge", {"id": str, "from": str, "to": str, "relation": str, "state": str, "provenance": NotRequired[GraphProvenance]})


class Graph(TypedDict):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    coverage: NotRequired[GraphCoverage]


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
    graphHistory: NotRequired[List[GraphObservation]]
    graphHistoryStatus: NotRequired[str]
    graphHistoryNote: NotRequired[str]


class RelationshipChange(TypedDict):
    relationship: str
    added: List[str]
    removed: List[str]


class SemanticDiff(TypedDict):
    fromObservation: NotRequired[str]
    toObservation: NotRequired[str]
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
    evidence: NotRequired[Evidence]
    coverage: NotRequired[GraphCoverage]
    resolver: NotRequired[Dict[str, str]]
    observation: NotRequired[GraphObservation]
    note: NotRequired[str]


class OperatorBindingEvidence(TypedDict):
    status: str  # VERIFIED | KEY_BOUND | UNVERIFIED_LINK | NOT_DECLARED | INVALID | INDETERMINATE
    declaredDid: NotRequired[str]
    claimSource: str  # MCP_DISCOVER_META | A2A_CARD_SIGNATURE | NONE
    endpointOrigin: str
    didOrigin: NotRequired[str]
    didServiceId: NotRequired[str]
    reverseDeclaration: NotRequired[str]  # DID_SERVICE_ENDPOINT | DID_ALSO_KNOWN_AS | SAME_DID_ORIGIN
    configurationStatus: NotRequired[str]
    configurationUrl: NotRequired[str]
    configurationSha256: NotRequired[str]
    detail: str


class OrganizationEvidence(TypedDict):
    status: str  # CONFIRMED | UNANCHORED | INACTIVE | INVALID
    lei: str
    carrier: str  # ISO_17442_2_EXTENSION | ETSI_ORG_IDENTIFIER
    snapshotStatus: str  # MATCHED | NOT_FOUND | NOT_CONFIGURED | UNAVAILABLE
    legalName: NotRequired[str]
    jurisdiction: NotRequired[str]
    entityStatus: NotRequired[str]
    registrationStatus: NotRequired[str]
    sourceAsOf: NotRequired[str]
    detail: str


class IssuerTrust(TypedDict):
    """SD-JWT VC issuer trust: categorical, never a score; EU trusted lists are never checked."""

    anchor: Literal["DID", "X509_CERTIFICATE", "ISSUER_METADATA", "NONE"]
    result: Literal["NOT_APPLICABLE", "NOT_ESTABLISHED", "CALLER_ANCHORED", "CHAIN_INVALID"]
    trustedListChecked: bool
    chain: NotRequired[List[Dict[str, Any]]]
    metadataUrl: NotRequired[str]
    organization: NotRequired[OrganizationEvidence]
    proves: str
    doesNotProve: str


class SdJwtEvidence(TypedDict):
    sdAlg: str
    disclosures: int
    decoyDigests: int
    registeredClaims: Dict[str, Any]
    keyBinding: Literal["VERIFIED", "ABSENT", "INVALID", "UNSUPPORTED", "INDETERMINATE"]


class ClaimRequirement(TypedDict):
    """A condition on an issuer-signed claim: JSON Pointer ``path`` equals ``equals``."""

    path: str
    equals: Union[bool, int, str]


class RequirementResult(TypedDict):
    path: str
    result: Literal["SATISFIED", "NOT_SATISFIED", "NOT_DISCLOSED", "NOT_EVALUATED"]


class RequirementsOutcome(TypedDict):
    """``met`` is True only when the credential is VALID and every condition is SATISFIED."""

    met: bool
    results: List[RequirementResult]


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
    issuerTrust: NotRequired["IssuerTrust"]
    sdJwt: NotRequired["SdJwtEvidence"]
    requirements: NotRequired["RequirementsOutcome"]
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
    linkedAccounts: List[str]
    verifiableHistory: Literal["required"]
    maxCacheAgeSeconds: int
    credentialStatus: Literal["active"]
    credentialIssuerMustBeSubject: bool
    organizationLei: str


class Policy(TypedDict):
    name: NotRequired[str]
    rules: PolicyRules


class SavedPolicyRefMeta(TypedDict):
    slug: str
    version: int
    reference: str
    rulesSha256: str


class PolicyVersionView(TypedDict):
    version: int
    reference: str
    description: NotRequired[str]
    rules: PolicyRules
    rulesSha256: str
    createdAt: int


class SavedPolicyProfile(TypedDict):
    slug: str
    currentVersion: int
    latestReference: str
    pinnedReference: str
    description: NotRequired[str]
    rules: PolicyRules
    rulesSha256: str
    createdAt: int
    updatedAt: int
    versions: List[PolicyVersionView]


class CustomerPoliciesResponse(TypedDict):
    policies: List[SavedPolicyProfile]
    limits: Dict[str, int]


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
    savedPolicy: NotRequired[SavedPolicyRefMeta]


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


class InventoryEvidence(TypedDict):
    scope: str
    pagesFetched: int
    entriesSeen: int
    entriesDropped: int
    hasMore: bool
    reasons: List[str]


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
    inventoryComplete: NotRequired[bool]
    inventoryEvidence: NotRequired[InventoryEvidence]
    jcsProfile: NotRequired[str]
    classCounts: Dict[str, int]
    drift: Dict[str, Any]
    auth: NotRequired[Dict[str, Any]]
    transcript: List[Dict[str, Any]]
    checks: List[Check]
    headline: str
    tls: NotRequired[Dict[str, Any]]
    operatorBinding: NotRequired[OperatorBindingEvidence]
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
    operatorBinding: NotRequired[OperatorBindingEvidence]
    limitations: List[str]


class DelegationLink(TypedDict):
    index: int
    issuer: str
    audience: str
    capabilities: List[str]
    notBefore: Optional[str]
    expires: Optional[str]
    jti: Optional[str]
    kid: Optional[str]
    alg: Optional[str]
    digest: str
    signatureValid: bool
    status: str
    issuerHeadline: NotRequired[str]
    checks: List[Check]


class DelegationChainResult(TypedDict):
    status: str
    headline: str
    format: str
    root: Optional[str]
    leaf: Optional[str]
    effectiveCapabilities: List[str]
    notAfter: Optional[str]
    trustedRoot: Optional[bool]
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
    documentSha256: Optional[str]
    observedAt: str
    cached: bool


class FastVerifyJwsResult(TypedDict):
    status: Literal["VALID", "INVALID", "INDETERMINATE", "UNSUPPORTED", "MALFORMED"]
    valid: bool
    headline: str
    alg: NotRequired[Optional[str]]
    kid: NotRequired[Optional[str]]
    typ: NotRequired[Optional[str]]
    payload: NotRequired[Any]
    signingInputSha256: NotRequired[str]
    signer: NotRequired[str]
    relationship: NotRequired[str]


class CustomerUsage(TypedDict):
    """``GET /v1/customer/usage``: this month's team allowance (all the team's projects share it)."""

    period: str
    standardUsed: int
    standardReserved: int
    standardLimit: int
    standardRemaining: int
    expensiveUsed: int
    expensiveReserved: int
    expensiveLimit: int
    expensiveRemaining: int
