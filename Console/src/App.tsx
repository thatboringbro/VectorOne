import { Fragment, useCallback, useEffect, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Clock3,
  FileWarning,
  Filter,
  HardDrive,
  History,
  ListFilter,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  Mail,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  UserRound,
  X,
} from 'lucide-react'
import './App.css'
import './auth.css'
import './response.css'
import './event-details.css'
import './fleet.css'

type EventRecord = {
  id: number
  filename: string
  username: string
  filetype: string
  datecreated: string
  filehash: string
  filepath: string
  device_name: string
  mitre_id: string | null
  mitre_tactics: string | null
  verdict: string
  response_status: string | null
  virustotal_result: string | null
  abuse_ch_result: string | null
}

type ResponseRecord = {
  id: number
  filepath: string
  action: string
  status: string
  created_at: string
  requested_by: number | null
  requested_by_name: string | null
  requested_by_email: string | null
  filename: string | null
  username: string | null
  filehash: string | null
  verdict: string
}

type AgentRecord = {
  agent_id: string
  hostname: string
  ip_address: string
  os_version: string
  status: 'online' | 'offline'
  last_seen: string
}

const API_BASE = (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')

type AnalystProfile = {
  id: number
  email: string
  full_name: string
  company_name: string
}

function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem('vectorone-session') || '')
  const [analyst, setAnalyst] = useState<AnalystProfile | null>(null)
  const [checkingSession, setCheckingSession] = useState(() => Boolean(sessionStorage.getItem('vectorone-session')))

  useEffect(() => {
    if (!token) return
    const controller = new AbortController()
    void fetch(`${API_BASE}/api/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: controller.signal,
    }).then(async (response) => {
      if (response.status === 401 || response.status === 403) {
        sessionStorage.removeItem('vectorone-session')
        setToken('')
        setAnalyst(null)
        return
      }
      if (!response.ok) throw new Error(`Session verification failed (${response.status})`)
      setAnalyst((await response.json()) as AnalystProfile)
    }).catch(() => {
      if (controller.signal.aborted) return
      sessionStorage.removeItem('vectorone-session')
      setToken('')
      setAnalyst(null)
    }).finally(() => {
      if (!controller.signal.aborted) setCheckingSession(false)
    })
    return () => controller.abort()
  }, [token])

  async function signIn(email: string, password: string) {
    const response = await fetch(`${API_BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })
    const result = await response.json()
    if (!response.ok) throw new Error(result.detail || 'Unable to sign in')
    sessionStorage.setItem('vectorone-session', result.access_token)
    setToken(result.access_token)
    setAnalyst(result.analyst as AnalystProfile)
  }

  async function signOut() {
    if (token) {
      void fetch(`${API_BASE}/api/auth/logout`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      })
    }
    sessionStorage.removeItem('vectorone-session')
    setToken('')
    setAnalyst(null)
    setCheckingSession(false)
  }

  if (checkingSession) return <div className="auth-loading"><LoaderCircle className="spin" size={19} /> VERIFYING ANALYST SESSION</div>
  if (!analyst || !token) return <LoginPage onSignIn={signIn} />
  return <Dashboard token={token} analyst={analyst} onSignOut={() => void signOut()} />
}

function Dashboard({ token, analyst, onSignOut }: { token: string; analyst: AnalystProfile; onSignOut: () => void }) {
  const [activeView, setActiveView] = useState<'events' | 'endpoints' | 'history'>('events')
  const [events, setEvents] = useState<EventRecord[]>([])
  const [query, setQuery] = useState('')
  const [verdictFilter, setVerdictFilter] = useState('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [queueingId, setQueueingId] = useState<number | null>(null)
  const [quarantineTarget, setQuarantineTarget] = useState<EventRecord | null>(null)
  const [expandedEventId, setExpandedEventId] = useState<number | null>(null)
  const [notice, setNotice] = useState('')
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const loadEvents = useCallback(async (showLoader = false) => {
    if (showLoader) setLoading(true)
    try {
      const response = await fetch(`${API_BASE}/api/events`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!response.ok) throw new Error(`Brain returned HTTP ${response.status}`)
      const data = (await response.json()) as EventRecord[]
      setEvents(data)
      setError('')
      setLastUpdated(new Date())
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Unable to reach the Brain')
    } finally {
      setLoading(false)
    }
  }, [token])

  useEffect(() => {
    const initialSync = window.setTimeout(() => void loadEvents(), 0)
    const timer = window.setInterval(() => void loadEvents(), 10_000)
    return () => {
      window.clearTimeout(initialSync)
      window.clearInterval(timer)
    }
  }, [loadEvents])

  async function queueQuarantine(event: EventRecord) {
    if (!event.filepath) {
      setNotice('No file path is stored for this event. New agent telemetry includes the full path.')
      return
    }

    setQueueingId(event.id)
    setNotice('')
    try {
      const response = await fetch(`${API_BASE}/api/commands/issue`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ filepath: event.filepath, action: 'quarantine' }),
      })
      const result = await response.json()
      if (!response.ok) throw new Error(result.detail || `Brain returned HTTP ${response.status}`)
      setNotice(`Quarantine command #${result.id} queued. The Agent will process it on its next poll.`)
      setQuarantineTarget(null)
      void loadEvents()
    } catch (queueError) {
      setNotice(queueError instanceof Error ? queueError.message : 'Unable to queue command')
    } finally {
      setQueueingId(null)
    }
  }

  const filteredEvents = events.filter((event) => {
    const matchesVerdict = verdictFilter === 'all' || event.verdict.toLowerCase() === verdictFilter
    const searchable = `${event.filename} ${event.filepath} ${event.filehash} ${event.username} ${event.mitre_id || ''}`.toLowerCase()
    return matchesVerdict && searchable.includes(query.toLowerCase())
  })
  const maliciousCount = events.filter((event) => event.verdict.toLowerCase() === 'malicious').length
  const suspiciousCount = events.filter((event) => event.verdict.toLowerCase() === 'suspicious').length

  return (
    <div className="console-shell">
      <aside className="rail" aria-label="Primary navigation">
        <div className="brand-mark"><ShieldAlert size={19} strokeWidth={1.8} /></div>
        <button className={`rail-item ${activeView === 'events' ? 'active' : ''}`} onClick={() => setActiveView('events')} aria-label="Detection events" title="Detection events"><Activity size={18} /></button>
        <button className={`rail-item ${activeView === 'endpoints' ? 'active' : ''}`} onClick={() => setActiveView('endpoints')} aria-label="Endpoints" title="Endpoints"><HardDrive size={18} /></button>
        <button className={`rail-item ${activeView === 'history' ? 'active' : ''}`} onClick={() => setActiveView('history')} aria-label="Response history" title="Response history"><History size={18} /></button>
        <div className="rail-spacer" />
        <button className="rail-item" aria-label="Help" title="Help"><CircleHelp size={18} /></button>
        <div className="operator-mark">SOC</div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div className="topbar-left">
            <span className="product-name">VECTOR<span>ONE</span></span>
            <span className="topbar-divider" />
            <span className="environment-label"><span className="online-dot" /> BRAIN LINK ACTIVE</span>
          </div>
          <div className="topbar-right">
            <span className="tenant-label">{analyst.company_name.toUpperCase()}</span>
            <span className="topbar-divider" />
            <span className="operator-name"><span className="operator-avatar">{analyst.full_name.slice(0, 1).toUpperCase()}</span><span className="operator-details"><strong>{analyst.full_name}</strong><small>{analyst.email}</small></span></span>
            <button className="signout-button" onClick={onSignOut} title="Sign out" aria-label="Sign out"><LogOut size={15} /></button>
          </div>
        </header>

        <div className="page-content">
          <div className="breadcrumb"><span>SECURITY OPERATIONS</span><span className="crumb-sep">/</span><strong>{activeView === 'events' ? 'DETECTION EVENTS' : activeView === 'endpoints' ? 'ENDPOINTS' : 'RESPONSE HISTORY'}</strong></div>
          <section className="page-heading">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" /> {activeView === 'events' ? 'ENDPOINT TELEMETRY' : activeView === 'endpoints' ? 'MANAGED ASSETS' : 'ANALYST RESPONSE AUDIT'}</div>
              <h1>{activeView === 'events' ? 'Detection events' : activeView === 'endpoints' ? 'Endpoints' : 'Response history'}</h1>
              <p className="subtitle">{activeView === 'events' ? 'File activity observed by VectorOne endpoint agents' : activeView === 'endpoints' ? 'Live connection health for registered VectorOne agents' : 'Threats and analyst-issued endpoint response actions'}</p>
            </div>
            <div className="heading-status">
              <span className="status-icon"><LockKeyhole size={15} /></span>
              <span>RESPONSE CONTROL</span>
              <span className="status-divider" />
              <span className="status-enabled">ENABLED</span>
            </div>
          </section>

          {activeView === 'events' && <section className="metric-strip" aria-label="Event summary">
            <div className="metric-cell">
              <div className="metric-label"><span>INGESTED EVENTS</span><Activity size={14} /></div>
              <div className="metric-value">{events.length.toString().padStart(2, '0')}<span className="metric-unit">TOTAL</span></div>
            </div>
            <div className="metric-cell alert-metric">
              <div className="metric-label"><span>MALICIOUS</span><AlertTriangle size={14} /></div>
              <div className="metric-value">{maliciousCount.toString().padStart(2, '0')}<span className="metric-unit">DETECTIONS</span></div>
            </div>
            <div className="metric-cell warning-metric">
              <div className="metric-label"><span>SUSPICIOUS</span><FileWarning size={14} /></div>
              <div className="metric-value">{suspiciousCount.toString().padStart(2, '0')}<span className="metric-unit">REVIEW</span></div>
            </div>
            <div className="metric-cell refresh-cell">
              <div className="metric-label"><span>LAST SYNCHRONIZED</span><Clock3 size={14} /></div>
              <div className="sync-value">{lastUpdated ? lastUpdated.toLocaleTimeString() : 'CONNECTING'}<span className="sync-pulse" /></div>
            </div>
          </section>}

          {notice && <div className="notice-bar" role="status"><span>{notice}</span><button onClick={() => setNotice('')} aria-label="Dismiss notice">×</button></div>}
          {error && <div className="error-bar" role="alert"><AlertTriangle size={15} /><span>Brain connection unavailable: {error}</span><span className="error-hint">VERIFY API BASE URL / CORS</span></div>}

          {activeView === 'events' ? <section className="events-panel">
            <div className="panel-header">
              <div className="panel-title"><span className="panel-index">01</span><h2>Event stream</h2><span className="result-count">{filteredEvents.length} RECORDS</span></div>
              <div className="panel-tools">
                <label className="search-control">
                  <Search size={15} />
                  <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search path, hash, host..." aria-label="Search events" />
                  <kbd>/</kbd>
                </label>
                <label className="filter-control"><Filter size={14} /><select value={verdictFilter} onChange={(event) => setVerdictFilter(event.target.value)} aria-label="Filter by verdict"><option value="all">All verdicts</option><option value="malicious">Malicious</option><option value="suspicious">Suspicious</option><option value="new">New</option><option value="duplicate">Duplicate</option></select><ChevronDown size={13} /></label>
                <button className="icon-button" onClick={() => void loadEvents(true)} title="Refresh events" aria-label="Refresh events"><RefreshCw size={15} className={loading ? 'spin' : ''} /></button>
              </div>
            </div>

            <div className="table-scroll">
              <table className="events-table">
                <thead><tr><th className="col-id">ID</th><th className="col-verdict">SEVERITY</th><th className="col-file">FILE / PATH</th><th className="col-mitre">MITRE ATT&amp;CK</th><th className="col-hash">SHA-256</th><th className="col-user">USER</th><th className="col-time">OBSERVED</th><th className="col-action"><span className="sr-only">Actions</span></th></tr></thead>
                <tbody>
                  {loading ? <tr><td colSpan={8} className="table-message"><LoaderCircle className="spin" size={17} /> Syncing event records</td></tr> : filteredEvents.length === 0 ? <tr><td colSpan={8} className="table-message"><ListFilter size={17} /> {error ? 'Waiting for Brain connection' : 'No matching event records'}</td></tr> : filteredEvents.map((event) => (
                    <Fragment key={event.id}>
                      <tr className={`event-row ${expandedEventId === event.id ? 'event-row-expanded' : ''}`} onClick={() => setExpandedEventId(expandedEventId === event.id ? null : event.id)}>
                        <td className="event-id">EV-{event.id.toString().padStart(5, '0')}</td>
                        <td><VerdictBadge verdict={event.verdict} /></td>
                        <td className="file-cell"><button className="event-expand-button" aria-expanded={expandedEventId === event.id} onClick={(clickEvent) => { clickEvent.stopPropagation(); setExpandedEventId(expandedEventId === event.id ? null : event.id) }}><ChevronRight size={13} /><span className="event-file-label"><span className="file-name">{event.filename}</span><span className="file-path" title={event.filepath || 'No filepath stored'}>{event.filepath || 'PATH NOT AVAILABLE'}</span></span></button></td>
                        <td><MitreBadge mitreId={event.mitre_id} tactics={event.mitre_tactics} /></td>
                        <td className="hash-cell" title={event.filehash}>{event.filehash}</td>
                        <td className="user-cell">{event.username}</td>
                        <td className="time-cell">{event.datecreated}</td>
                        <td className="action-cell">{event.response_status ? <ResponseStatus status={event.response_status} /> : <button className="quarantine-button" disabled={!event.filepath || queueingId === event.id} onClick={(clickEvent) => { clickEvent.stopPropagation(); setQuarantineTarget(event) }} title={!event.filepath ? 'No filepath is available for this event' : 'Open quarantine confirmation'}>{queueingId === event.id ? <LoaderCircle size={13} className="spin" /> : <ShieldAlert size={13} />}<span>QUARANTINE</span></button>}</td>
                      </tr>
                      {expandedEventId === event.id && <tr className="details-row" key={`${event.id}-details`}><td colSpan={8}><EventDetails event={event} /></td></tr>}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>
            <footer className="table-footer"><div><span className="footer-live-dot" /> LIVE POLL <span className="footer-separator">/</span> 10 SEC</div><div>SHOWING {filteredEvents.length} OF {events.length} EVENTS <span className="footer-separator">/</span> <span className="footer-lock"><ShieldCheck size={12} /> COMMANDS REQUIRE ANALYST ACTION</span></div></footer>
          </section> : activeView === 'endpoints' ? <EndpointsPanel token={token} /> : <ResponseHistoryPanel token={token} />}
          <footer className="page-footer"><span>VECTORONE SECURITY PLATFORM</span><span>ENDPOINT RESPONSE <b>●</b> OPERATIONAL</span></footer>
        </div>
      </main>
      {quarantineTarget && <QuarantineModal event={quarantineTarget} busy={queueingId === quarantineTarget.id} onCancel={() => setQuarantineTarget(null)} onConfirm={() => void queueQuarantine(quarantineTarget)} />}
    </div>
  )
}

function EndpointsPanel({ token }: { token: string }) {
  const [agents, setAgents] = useState<AgentRecord[]>([])
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const loadAgents = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/api/agents`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!response.ok) throw new Error(`Brain returned HTTP ${response.status}`)
      setAgents((await response.json()) as AgentRecord[])
      setError('')
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Unable to load agent fleet')
    } finally {
      setLoading(false)
    }
  }, [token])

  useEffect(() => {
    const initialLoad = window.setTimeout(() => void loadAgents(), 0)
    const poll = window.setInterval(() => void loadAgents(), 10_000)
    return () => {
      window.clearTimeout(initialLoad)
      window.clearInterval(poll)
    }
  }, [loadAgents])

  const filteredAgents = agents.filter((agent) =>
    `${agent.hostname} ${agent.ip_address} ${agent.os_version} ${agent.agent_id}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  )
  const activeCount = agents.filter((agent) => agent.status === 'online').length
  const offlineCount = agents.length - activeCount

  return <>
    <section className="metric-strip fleet-metrics" aria-label="Endpoint fleet summary">
      <div className="metric-cell"><div className="metric-label"><span>TOTAL ENDPOINTS</span><HardDrive size={14} /></div><div className="metric-value">{agents.length.toString().padStart(2, '0')}<span className="metric-unit">REGISTERED</span></div></div>
      <div className="metric-cell fleet-online-metric"><div className="metric-label"><span>ACTIVE AGENTS</span><Check size={14} /></div><div className="metric-value">{activeCount.toString().padStart(2, '0')}<span className="metric-unit">ONLINE</span></div></div>
      <div className="metric-cell alert-metric"><div className="metric-label"><span>OFFLINE FLEET COUNT</span><AlertTriangle size={14} /></div><div className="metric-value">{offlineCount.toString().padStart(2, '0')}<span className="metric-unit">OFFLINE</span></div></div>
    </section>
    {error && <div className="error-bar" role="alert"><AlertTriangle size={15} /><span>Agent fleet unavailable: {error}</span></div>}
    <section className="events-panel">
      <div className="panel-header">
        <div className="panel-title"><span className="panel-index">03</span><h2>Agent fleet</h2><span className="result-count">{filteredAgents.length} NODES</span></div>
        <div className="panel-tools">
          <label className="search-control"><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search host, IP, OS..." aria-label="Search agents" /><kbd>/</kbd></label>
          <button className="icon-button" onClick={() => void loadAgents()} title="Refresh agent fleet" aria-label="Refresh agent fleet"><RefreshCw size={15} /></button>
        </div>
      </div>
      <div className="table-scroll">
        <table className="fleet-table">
          <thead><tr><th>HOSTNAME</th><th>IP ADDRESS</th><th>OPERATING SYSTEM</th><th>STATUS</th><th>LAST SEEN (UTC)</th></tr></thead>
          <tbody>
            {loading ? <tr><td colSpan={5} className="table-message"><LoaderCircle className="spin" size={17} /> Loading agent fleet</td></tr> : filteredAgents.length === 0 ? <tr><td colSpan={5} className="table-message"><ListFilter size={17} /> {error ? 'Waiting for Brain connection' : 'No registered agents match this search'}</td></tr> : filteredAgents.map((agent) => (
              <tr key={agent.agent_id}>
                <td className="fleet-hostname" title={agent.agent_id}>{agent.hostname}</td>
                <td className="fleet-mono">{agent.ip_address || 'Not reported'}</td>
                <td className="fleet-os" title={agent.os_version}>{agent.os_version || 'Not reported'}</td>
                <td><span className={`agent-status agent-status-${agent.status}`}>{agent.status}</span></td>
                <td className="fleet-mono">{new Date(agent.last_seen).toISOString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <footer className="table-footer"><div><span className="footer-live-dot" /> AUTO-REFRESH <span className="footer-separator">/</span> 10 SEC</div><div>SHOWING {filteredAgents.length} OF {agents.length} ENDPOINTS <span className="footer-separator">/</span> OFFLINE AFTER 180 SEC</div></footer>
    </section>
  </>
}

function ResponseHistoryPanel({ token }: { token: string }) {
  const [records, setRecords] = useState<ResponseRecord[]>([])
  const [query, setQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [verdictFilter, setVerdictFilter] = useState('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const loadHistory = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/api/commands/history`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!response.ok) throw new Error(`Brain returned HTTP ${response.status}`)
      setRecords((await response.json()) as ResponseRecord[])
      setError('')
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Unable to load response history')
    } finally {
      setLoading(false)
    }
  }, [token])

  useEffect(() => {
    const initialLoad = window.setTimeout(() => void loadHistory(), 0)
    const poll = window.setInterval(() => void loadHistory(), 10_000)
    return () => {
      window.clearTimeout(initialLoad)
      window.clearInterval(poll)
    }
  }, [loadHistory])

  const filteredRecords = records.filter((record) => {
    const matchesStatus = statusFilter === 'all' || record.status === statusFilter
    const matchesVerdict = verdictFilter === 'all' || record.verdict.toLowerCase() === verdictFilter
    const searchable = `${record.filename || ''} ${record.filepath} ${record.filehash || ''} ${record.requested_by_name || ''} ${record.requested_by_email || ''}`.toLowerCase()
    return matchesStatus && matchesVerdict && searchable.includes(query.toLowerCase())
  })
  const completedCount = records.filter((record) => record.status === 'completed').length
  const pendingCount = records.filter((record) => record.status === 'pending').length
  const threatCount = records.filter((record) => record.verdict.toLowerCase() === 'malicious').length

  return (
    <>
      <section className="metric-strip history-metrics" aria-label="Response summary">
        <div className="metric-cell"><div className="metric-label"><span>RESPONSE ACTIONS</span><History size={14} /></div><div className="metric-value">{records.length.toString().padStart(2, '0')}<span className="metric-unit">TOTAL</span></div></div>
        <div className="metric-cell alert-metric"><div className="metric-label"><span>THREAT FILES</span><ShieldAlert size={14} /></div><div className="metric-value">{threatCount.toString().padStart(2, '0')}<span className="metric-unit">MALICIOUS</span></div></div>
        <div className="metric-cell warning-metric"><div className="metric-label"><span>AWAITING AGENT</span><Clock3 size={14} /></div><div className="metric-value">{pendingCount.toString().padStart(2, '0')}<span className="metric-unit">QUEUED</span></div></div>
        <div className="metric-cell completed-metric"><div className="metric-label"><span>EXECUTED</span><Check size={14} /></div><div className="metric-value">{completedCount.toString().padStart(2, '0')}<span className="metric-unit">COMPLETED</span></div></div>
      </section>

      {error && <div className="error-bar" role="alert"><AlertTriangle size={15} /><span>Response history unavailable: {error}</span></div>}

      <section className="events-panel">
        <div className="panel-header">
          <div className="panel-title"><span className="panel-index">02</span><h2>Response audit trail</h2><span className="result-count">{filteredRecords.length} RECORDS</span></div>
          <div className="panel-tools">
            <label className="search-control"><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search target, hash, analyst..." aria-label="Search response history" /><kbd>/</kbd></label>
            <label className="filter-control"><Filter size={14} /><select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} aria-label="Filter response status"><option value="all">All statuses</option><option value="pending">Queued</option><option value="completed">Completed</option></select><ChevronDown size={13} /></label>
            <label className="filter-control"><ShieldAlert size={14} /><select value={verdictFilter} onChange={(event) => setVerdictFilter(event.target.value)} aria-label="Filter threat verdict"><option value="all">All verdicts</option><option value="malicious">Malicious</option><option value="suspicious">Suspicious</option><option value="new">New</option><option value="unknown">Unknown</option></select><ChevronDown size={13} /></label>
            <button className="icon-button" onClick={() => void loadHistory()} title="Refresh response history" aria-label="Refresh response history"><RefreshCw size={15} /></button>
          </div>
        </div>
        <div className="table-scroll">
          <table className="history-table">
            <thead><tr><th>COMMAND</th><th>OUTCOME</th><th>THREAT</th><th>FILE / TARGET</th><th>SHA-256</th><th>REQUESTED BY</th><th>QUEUED AT</th></tr></thead>
            <tbody>
              {loading ? <tr><td colSpan={7} className="table-message"><LoaderCircle className="spin" size={17} /> Loading response actions</td></tr> : filteredRecords.length === 0 ? <tr><td colSpan={7} className="table-message"><ListFilter size={17} /> {error ? 'Waiting for Brain connection' : 'No response actions match these filters'}</td></tr> : filteredRecords.map((record) => (
                <tr key={record.id}>
                  <td className="event-id">RC-{record.id.toString().padStart(5, '0')}</td>
                  <td><ResponseStatus status={record.status} /></td>
                  <td><VerdictBadge verdict={record.verdict} /></td>
                  <td className="file-cell"><span className="file-name">{record.filename || 'Unlinked target'}</span><span className="file-path" title={record.filepath}>{record.filepath}</span></td>
                  <td className="hash-cell" title={record.filehash || ''}>{record.filehash || 'N/A'}</td>
                  <td className="user-cell">{record.requested_by_name || record.requested_by_email || 'Legacy command'}</td>
                  <td className="time-cell">{record.created_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <footer className="table-footer"><div><span className="footer-live-dot" /> AUTO-REFRESH <span className="footer-separator">/</span> 10 SEC</div><div>SHOWING {filteredRecords.length} OF {records.length} ACTIONS <span className="footer-separator">/</span> ANALYST RESPONSE AUDIT</div></footer>
      </section>
    </>
  )
}

function EventDetails({ event }: { event: EventRecord }) {
  return <div className="event-details" onClick={(clickEvent) => clickEvent.stopPropagation()}>
    <section className="detail-section endpoint-section">
      <div className="detail-section-heading"><UserRound size={14} /><h3>Endpoint and file</h3><span>OBSERVED ENTITY</span></div>
      <dl className="detail-grid">
        <DetailField label="DEVICE NAME" value={event.device_name || 'Not reported'} />
        <DetailField label="USER" value={event.username || 'Not reported'} />
        <DetailField label="FILE TYPE" value={event.filetype || 'Unknown'} />
        <DetailField label="OBSERVED AT" value={event.datecreated || 'Unknown'} />
        <div className="detail-field detail-field-wide"><dt>MITRE ATT&amp;CK</dt><dd><MitreBadge mitreId={event.mitre_id} tactics={event.mitre_tactics} />{event.mitre_tactics && <span className="mitre-tactic">TACTIC: {event.mitre_tactics}</span>}</dd></div>
        <DetailField label="FILE PATH" value={event.filepath || 'Not available'} mono wide />
        <DetailField label="SHA-256" value={event.filehash || 'Not available'} mono wide />
      </dl>
    </section>
    <section className="detail-section cti-section">
      <div className="detail-section-heading"><ShieldCheck size={14} /><h3>Threat intelligence</h3><span>STORED PROVIDER CHECKS</span></div>
      <div className="provider-grid">
        <ProviderCheck name="VIRUSTOTAL" serializedResult={event.virustotal_result} />
        <ProviderCheck name="ABUSE.CH / MALWAREBAZAAR" serializedResult={event.abuse_ch_result} />
      </div>
    </section>
  </div>
}

function MitreBadge({ mitreId, tactics }: { mitreId: string | null; tactics: string | null }) {
  if (!mitreId) return <span className="mitre-unmapped">NOT MAPPED</span>

  const techniqueName = mitreId === 'T1204.002' ? 'User Execution' : tactics || 'ATT&CK'
  return <span className="mitre-badge" title={`MITRE ATT&CK tactic: ${tactics || 'Not reported'}`}>
    {mitreId} - {techniqueName}
  </span>
}

function DetailField({ label, value, mono = false, wide = false }: { label: string; value: string; mono?: boolean; wide?: boolean }) {
  return <div className={`detail-field ${wide ? 'detail-field-wide' : ''}`}><dt>{label}</dt><dd className={mono ? 'detail-mono' : ''} title={value}>{value}</dd></div>
}

function ProviderCheck({ name, serializedResult }: { name: string; serializedResult: string | null }) {
  let result: Record<string, unknown> | null = null
  try {
    result = serializedResult ? JSON.parse(serializedResult) as Record<string, unknown> : null
  } catch {
    result = null
  }

  const available = result?.available === true
  const malicious = Number(result?.malicious || 0) > 0 || result?.malicious === true
  const suspicious = Number(result?.suspicious || 0) > 0
  const stats = result?.stats && typeof result.stats === 'object' ? result.stats as Record<string, unknown> : null
  const results = Array.isArray(result?.results) ? result.results : []
  const error = typeof result?.error === 'string' ? result.error : ''
  const state = !result ? 'NO SNAPSHOT' : !available ? 'UNAVAILABLE' : malicious ? 'MALICIOUS' : suspicious ? 'SUSPICIOUS' : 'NO DETECTION'

  return <article className="provider-card">
    <div className="provider-card-heading"><span>{name}</span><span className={`provider-state ${malicious ? 'provider-state-bad' : suspicious ? 'provider-state-warn' : available ? 'provider-state-clear' : ''}`}>{state}</span></div>
    {!result ? <p className="provider-note">No stored result for this event.</p> : <>
      {stats && <div className="provider-stats">{Object.entries(stats).map(([key, value]) => <div key={key}><span>{key.toUpperCase()}</span><strong>{String(value)}</strong></div>)}</div>}
      {name.startsWith('ABUSE') && <>
        <p className="provider-note">{results.length} matching sample{results.length === 1 ? '' : 's'} in stored provider response.</p>
        {results.slice(0, 2).map((item, index) => {
          const sample = item && typeof item === 'object' ? item as Record<string, unknown> : {}
          return <div className="abuse-sample" key={String(sample.sha256_hash || index)}><strong>{String(sample.signature || sample.file_name || 'MalwareBazaar match')}</strong><span>{String(sample.first_seen || sample.file_type || sample.sha256_hash || '')}</span></div>
        })}
      </>}
      {error && <p className="provider-note provider-error">{error}</p>}
      {!available && !error && <p className="provider-note">Provider lookup was unavailable when this event was analyzed.</p>}
    </>}
  </article>
}

function QuarantineModal({ event, busy, onCancel, onConfirm }: { event: EventRecord; busy: boolean; onCancel: () => void; onConfirm: () => void }) {
  useEffect(() => {
    const onKeyDown = (keyboardEvent: KeyboardEvent) => {
      if (keyboardEvent.key === 'Escape' && !busy) onCancel()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [busy, onCancel])

  return <div className="modal-backdrop" onMouseDown={(mouseEvent) => { if (mouseEvent.target === mouseEvent.currentTarget && !busy) onCancel() }}>
    <section className="quarantine-modal" role="dialog" aria-modal="true" aria-labelledby="quarantine-title" aria-describedby="quarantine-description">
      <header className="modal-header"><span className="modal-icon"><ShieldAlert size={17} /></span><div><span className="modal-kicker">ANALYST RESPONSE</span><h2 id="quarantine-title">Quarantine file</h2></div><button className="modal-close" onClick={onCancel} disabled={busy} aria-label="Close dialog"><X size={17} /></button></header>
      <div className="modal-content">
        <p id="quarantine-description">This queues a quarantine action for the endpoint Agent. The file will be removed from its current location when the Agent processes the command.</p>
        <div className="modal-target"><span>TARGET FILE</span><strong>{event.filename}</strong><code>{event.filepath}</code></div>
        <div className="modal-context"><span><b>VERDICT</b><VerdictBadge verdict={event.verdict} /></span><span><b>DEVICE</b>{event.device_name || 'Unknown device'}</span><span><b>USER</b>{event.username || 'Unknown user'}</span></div>
      </div>
      <footer className="modal-actions"><button className="modal-cancel" onClick={onCancel} disabled={busy}>CANCEL</button><button className="modal-confirm" onClick={onConfirm} disabled={busy}>{busy ? <LoaderCircle size={14} className="spin" /> : <ShieldAlert size={14} />}<span>{busy ? 'QUEUEING' : 'QUEUE QUARANTINE'}</span></button></footer>
    </section>
  </div>
}

function LoginPage({ onSignIn }: { onSignIn: (email: string, password: string) => Promise<void> }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setSubmitting(true)
    try {
      await onSignIn(email, password)
    } catch (signInError) {
      setError(signInError instanceof Error ? signInError.message : 'Unable to sign in')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="login-screen">
      <section className="login-identity">
        <div className="login-brand"><span className="login-brand-mark"><ShieldAlert size={20} /></span><span>VECTOR<span>ONE</span></span></div>
        <div className="identity-content">
          <div className="eyebrow"><span className="eyebrow-line" /> SECURITY OPERATIONS PLATFORM</div>
          <h1>Endpoint visibility.<br /><span>Analyst-controlled response.</span></h1>
          <div className="identity-rule" />
          <div className="identity-metadata"><div><span>CONTROL PLANE</span><strong>VECTORONE BRAIN</strong></div><div><span>ACCESS SCOPE</span><strong>AUTHORIZED ANALYSTS</strong></div></div>
        </div>
        <div className="login-footnote"><span>VECTORONE SECURITY PLATFORM</span><span>INTERNAL OPERATIONS</span></div>
      </section>
      <section className="login-form-side">
        <div className="login-form-wrap">
          <div className="login-kicker"><LockKeyhole size={14} /> SECURE ANALYST ACCESS</div>
          <h2>Sign in</h2>
          <p className="login-intro">Use your provisioned analyst account to access endpoint telemetry.</p>
          <form onSubmit={(event) => void handleSubmit(event)}>
            <label className="login-label" htmlFor="analyst-email">WORK EMAIL</label>
            <div className="login-input-wrap"><Mail size={15} /><input id="analyst-email" type="email" autoComplete="username" required value={email} onChange={(event) => setEmail(event.target.value)} placeholder="analyst@company.com" /></div>
            <label className="login-label password-label" htmlFor="analyst-password">PASSWORD</label>
            <div className="login-input-wrap"><LockKeyhole size={15} /><input id="analyst-password" type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Enter your password" /></div>
            {error && <div className="login-error" role="alert"><AlertTriangle size={14} />{error}</div>}
            <button className="login-submit" type="submit" disabled={submitting}>{submitting ? <LoaderCircle className="spin" size={15} /> : <LockKeyhole size={15} />}<span>{submitting ? 'AUTHENTICATING' : 'AUTHENTICATE'}</span></button>
          </form>
          <div className="login-policy"><ShieldCheck size={14} /><span>Account access is provisioned by your VectorOne administrator.</span></div>
        </div>
        <div className="login-side-footer"><span>SESSION ENCRYPTION ACTIVE</span><span>BUILD 1.0.0</span></div>
      </section>
    </main>
  )
}

function VerdictBadge({ verdict }: { verdict: string }) {
  const normalized = verdict.toLowerCase()
  const icon = normalized === 'malicious' ? <ShieldAlert size={13} /> : normalized === 'suspicious' ? <AlertTriangle size={13} /> : <Check size={13} />
  return <span className={`verdict-badge verdict-${normalized}`}><span className="verdict-icon">{icon}</span>{normalized.toUpperCase()}</span>
}

function ResponseStatus({ status }: { status: string }) {
  const completed = status === 'completed'
  return <span className={`response-status ${completed ? 'response-completed' : 'response-pending'}`}>
    {completed ? <Check size={12} /> : <Clock3 size={12} />}
    {completed ? 'REMOVED' : 'QUEUED'}
  </span>
}

export default App
