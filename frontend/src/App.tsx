import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { ChangeDevName, GetDevices, SetBlocked, SetRateLimit, Status, GetIface, GetIpfwd, GetIfacefwd } from '../bindings/github.com/saif/spoofer/deviceservice'
import type { DeviceView } from '../bindings/github.com/saif/spoofer/models'

type Page = 'devices' | 'activity' | 'rules' | 'settings'

type Unit = 'kb' | 'mb' | 'gb'

// Decimal, matching formatRate: 1 kb = 1000 bytes.
const unitToKb: Record<Unit, number> = { kb: 1, mb: 1000, gb: 1000 * 1000 }

type Direction = 'up' | 'down'

// Control box state lives per device key and survives table hops. A row that
// moves between the reachable and unreachable tables is a React remount, so
// anything held only in component state dies at the flip; this map is owned
// by DevicesPage and passed down, so it outlives every remount.
type ControlStore = Map<string, DeviceControlState>

type DeviceControlState = {
    up: string
    down: string
    upUnit: Unit
    downUnit: Unit
    seeded: boolean
    applied: Record<Direction, number | null>
}

// getControlState reads the entry for one device, creating an empty one so the
// caller can write through without first consulting every field.
function getControlState(store: ControlStore, key: string): DeviceControlState {
    let s = store.get(key)
    if (!s) {
        s = {
            up: '',
            down: '',
            upUnit: 'kb',
            downUnit: 'kb',
            seeded: false,
            applied: { up: null, down: null },
        }
        store.set(key, s)
    }
    return s
}

function RateControl({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
    return (
        <label className="rate-control">
            <span className="rate-label">{label}</span>
            <input
                className="rate-input"
                type="number"
                min="0"
                placeholder="0"
                value={value}
                onChange={(e) => onChange(e.target.value)}
            />
        </label>
    )
}

function DeviceControls({ device, controls, onError, onChanged }: {
    device: DeviceView
    controls: ControlStore
    onError: (msg: string) => void
    onChanged: () => Promise<void>
}) {
    // The per-device entry is stable across the remounts a table hop causes,
    // so local state is initialised from it and mirrored back on every edit;
    // either way the box never loses what the user typed.
    const key = `${device.ip}|${device.mac}`
    const saved = getControlState(controls, key)

    const [up, setUpRaw] = useState(saved.up)
    const setUp = (v: string) => { saved.up = v; setUpRaw(v) }
    const [down, setDownRaw] = useState(saved.down)
    const setDown = (v: string) => { saved.down = v; setDownRaw(v) }
    const [upUnit, setUpUnitRaw] = useState<Unit>(saved.upUnit)
    const setUpUnit = (v: Unit) => { saved.upUnit = v; setUpUnitRaw(v) }
    const [downUnit, setDownUnitRaw] = useState(saved.downUnit)
    const setDownUnit = (v: Unit) => { saved.downUnit = v; setDownUnitRaw(v) }

    // The engine owns the truth. pending only covers the window between the
    // click and the call settling, then drops back to null so the checkbox
    // renders whatever the engine actually reports - including rolling itself
    // back when the call failed. It stays local on purpose: a remount simply
    // shows the engine's answer instead of carrying a stale pending across.
    const blocked = (device.state ?? []).includes('blocked')
    const [pending, setPending] = useState<boolean | null>(null)
    const shown = pending ?? blocked

    async function toggleBlock(checked: boolean) {
        setPending(checked)
        try {
            await SetBlocked(device.ip, checked)
        } catch (err) {
            onError(String(err))
        }
        try {
            // Pull the engine's answer now instead of waiting out the poll.
            await onChanged()
        } finally {
            setPending(null)
        }
    }
    // Seed the boxes from the live limit once it first appears, so a box starts
    // at the cap already in force rather than reading as 0. The flag lives in
    // the shared store, so a remount does not re-seed or double-apply.
    useEffect(() => {
        if (saved.seeded) return
        const upKB = device.upLimitKB ?? 0
        const downKB = device.downLimitKB ?? 0
        if (upKB > 0) {
            setUp(String(Math.round(upKB)))
            setUpUnit(upKB >= 1000 * 1000 ? 'gb' : upKB >= 1000 ? 'mb' : 'kb')
        }
        if (downKB > 0) {
            setDown(String(Math.round(downKB)))
            setDownUnit(downKB >= 1000 * 1000 ? 'gb' : downKB >= 1000 ? 'mb' : 'kb')
        }
        if (upKB > 0 || downKB > 0) saved.seeded = true
    }, [device.upLimitKB, device.downLimitKB])

    // Last value handed to the engine per direction, so an edit that lands back on
    // what is already applied sends nothing. null until the first send. The
    // record is the store's own object, so it also survives remounts.
    const applied = saved.applied
    const timers = useRef<Record<Direction, number>>({ up: 0, down: 0 })

    async function sendLimit(dir: Direction, raw: string, unit: Unit) {
        // The engine wants kb/s as a plain number; a blank box reads as 0,
        // which the engine takes as "clear this".
        const rate = (Number(raw) || 0) * unitToKb[unit]
        if (applied[dir] === rate) return
        try {
            await SetRateLimit(device.ip, dir, rate)
            // Only on success, so a failed edit is retried rather than
            // remembered as already in force.
            applied[dir] = rate
            await onChanged()
        } catch (err) {
            onError(String(err))
        }
    }

    // Each direction keeps its own timer: editing one box must not swallow the
    // other's pending send, and the wait collapses a burst of keystrokes into
    // one call.
    function edit(dir: Direction, value: string, unit: Unit) {
        if (dir === 'up') setUp(value)
        else setDown(value)
        window.clearTimeout(timers.current[dir])
        timers.current[dir] = window.setTimeout(() => sendLimit(dir, value, unit), 500)
    }

    // The boxes are written through to the store on every keystroke, so at
    // unmount the store already holds the latest text: flush an edit that was
    // still inside its debounce instead of dropping it, which is what used to
    // happen when a row hopped tables mid-edit.
    useEffect(() => () => {
        for (const dir of ['up', 'down'] as const) {
            if (timers.current[dir]) {
                window.clearTimeout(timers.current[dir])
                timers.current[dir] = 0
                void sendLimit(
                    dir,
                    dir === 'up' ? saved.up : saved.down,
                    dir === 'up' ? saved.upUnit : saved.downUnit,
                )
            }
        }
    }, [])

    return (
        <div className="device-controls">
            <div className="rate-pair">
                <RateControl label="Up" value={up} onChange={(v) => edit('up', v, upUnit)} />
                <select className="rate-select" value={upUnit} onChange={(e) => setUpUnit(e.target.value as Unit)}>
                    <option value="kb">kb</option>
                    <option value="mb">mb</option>
                    <option value="gb">gb</option>
                </select>
            </div>
            <div className="rate-pair">
                <RateControl label="Down" value={down} onChange={(v) => edit('down', v, downUnit)} />
                <select className="rate-select" value={downUnit} onChange={(e) => setDownUnit(e.target.value as Unit)}>
                    <option value="kb">kb</option>
                    <option value="mb">mb</option>
                    <option value="gb">gb</option>
                </select>
            </div>
            <label className="block-check">
                <input
                    type="checkbox"
                    checked={shown}
                    disabled={pending !== null}
                    onChange={(e) => toggleBlock(e.target.checked)}
                />
                <span>Block</span>
            </label>
        </div>
    )
}

// NameCell turns the device name into an inline editor. The engine keys the
// rename by MAC, so no lookup happens here.
function NameCell({ device, onError, onChanged }: {
    device: DeviceView
    onError: (msg: string) => void
    onChanged: () => Promise<void>
}) {
    const [editing, setEditing] = useState(false)
    const [value, setValue] = useState(device.name)
    const [saving, setSaving] = useState(false)
    // Escape blurs the input to leave edit mode, and that blur would otherwise
    // commit the text the user just rejected.
    const skipSave = useRef(false)

    // Follow the engine while idle, so a poll refresh or an edit from
    // somewhere else shows up.
    useEffect(() => {
        if (!editing) setValue(device.name)
    }, [device.name, editing])

    async function commit() {
        setEditing(false)
        if (skipSave.current) {
            skipSave.current = false
            return
        }
        const next = value.trim()
        if (next === '' || next === device.name) {
            setValue(device.name)
            return
        }
        setSaving(true)
        try {
            await ChangeDevName(device.mac, next)
            // Pull the engine's answer now instead of waiting out the poll.
            await onChanged()
        } catch (err) {
            onError(String(err))
            setValue(device.name)
        } finally {
            setSaving(false)
        }
    }

    if (!editing) {
        return (
            <button
                type="button"
                className="name-cell"
                title="Click to rename"
                disabled={saving}
                onClick={() => {
                    skipSave.current = false
                    setValue(device.name)
                    setEditing(true)
                }}
            >
                {device.name || '—'}
            </button>
        )
    }

    return (
        <input
            className="name-input"
            autoFocus
            maxLength={64}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onBlur={commit}
            onKeyDown={(e) => {
                if (e.key === 'Enter') {
                    e.currentTarget.blur()
                } else if (e.key === 'Escape') {
                    skipSave.current = true
                    e.currentTarget.blur()
                }
            }}
        />
    )
}

function DeviceRow({ device, controls, onError, onChanged }: {
    device: DeviceView
    controls: ControlStore
    onError: (msg: string) => void
    onChanged: () => Promise<void>
}) {
    return (
        <tr>
            <td><NameCell device={device} onError={onError} onChanged={onChanged} /></td>
            <td>{device.ip}</td>
            <td>{device.mac}</td>
            <td>{device.vendor}</td>
            <td className="rate-cell">
                {device.upRate}
                {device.upLimit && <span className="limit-note">cap {device.upLimit}</span>}
            </td>
            <td className="rate-cell">
                {device.downRate}
                {device.downLimit && <span className="limit-note">cap {device.downLimit}</span>}
            </td>
            <td>
                <div className="badges">
                    {(device.state ?? []).map((s) => (
                        <span key={s} className={`badge badge-${s}`}>{s}</span>
                    ))}
                </div>
            </td>
            <td className="rate-cell totals-cell">
                <span>Down: {device.totalDown}</span>
                <span>Up: {device.totalUp}</span>
            </td>
            <td className="controls-col"><DeviceControls device={device} controls={controls} onError={onError} onChanged={onChanged} /></td>
        </tr>
    )
}

function DeviceTable({ devices, controls, empty, onError, onChanged, className = '' }: {
    devices: DeviceView[]
    controls: ControlStore
    empty: string
    onError: (msg: string) => void
    onChanged: () => Promise<void>
    className?: string
}) {
    return (
        <div className={`table-wrap ${className}`}>
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>IP</th>
                        <th>MAC</th>
                        <th>Vendor</th>
                        <th className="rate-head">Up</th>
                        <th className="rate-head">Down</th>
                        <th>State</th>
                        <th className="rate-head">Total</th>
                        <th className="controls-head">Controls</th>
                    </tr>
                </thead>
                <tbody>
                    {devices.length === 0
                        ? <tr><td colSpan={9} className="empty-row">{empty}</td></tr>
                        : devices.map((d) => (
                            <DeviceRow
                                key={`${d.ip}|${d.mac}`}
                                device={d}
                                controls={controls}
                                onError={onError}
                                onChanged={onChanged}
                            />
                        ))}
                </tbody>
            </table>
        </div>
    )
}

// Host and gateway are pulled out of the main list: they are context, not
// peers to shape, so they get read-only rows above the device tables.
function RoleRow({ role, device }: { role: 'host' | 'gateway'; device?: DeviceView }) {
    const label = role === 'host' ? 'Host' : 'Gateway'
    if (!device) {
        return (
            <tr className={`summary-row role-row-${role}`}>
                <td><span className={`role-badge role-${role}`}>{label}</span></td>
                <td colSpan={8} className="muted">not detected yet</td>
            </tr>
        )
    }
    return (
        <tr className={`summary-row role-row-${role}`}>
            <td>
                <span className={`role-badge role-${role}`}>{label}</span>
                {device.name || '—'}
            </td>
            <td>{device.ip || '—'}</td>
            <td>{device.mac || '—'}</td>
            <td>{device.vendor || '—'}</td>
            <td className="rate-cell">{device.upRate}</td>
            <td className="rate-cell">{device.downRate}</td>
            <td>
                <div className="badges">
                    {(device.state ?? []).map((s) => (
                        <span key={s} className={`badge badge-${s}`}>{s}</span>
                    ))}
                </div>
            </td>
            <td className="rate-cell totals-cell">
                <span>Down: {device.totalDown}</span>
                <span>Up: {device.totalUp}</span>
            </td>
            <td />
        </tr>
    )
}

function TopologyTable({ host, gateway }: { host?: DeviceView; gateway?: DeviceView }) {
    return (
        <div className="table-wrap summary-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>IP</th>
                        <th>MAC</th>
                        <th>Vendor</th>
                        <th className="rate-head">Up</th>
                        <th className="rate-head">Down</th>
                        <th>State</th>
                        <th className="rate-head">Total</th>
                        <th className="controls-head" />
                    </tr>
                </thead>
                <tbody>
                    <RoleRow role="host" device={host} />
                    <RoleRow role="gateway" device={gateway} />
                </tbody>
            </table>
        </div>
    )
}

function DevicesPage() {
    const [devices, setDevices] = useState<DeviceView[]>([])
    const [error, setError] = useState('')
    const [startupError, setStartupError] = useState('')
    // Session-wide transfer counters, carried on the Status poll.
    const [totals, setTotals] = useState({ sent: '', received: '' })

    // Shared by the 1s poll and the block toggle, so a toggle does not sit
    // waiting a full tick for the engine's answer.
    const refresh = useCallback(async () => {
        const [result, status] = await Promise.all([GetDevices(), Status()])
        setDevices(result ?? [])
        setStartupError(status?.error ?? '')
        setTotals({ sent: status?.sent ?? '', received: status?.received ?? '' })
    }, [])

    // Lives for as long as the devices page does; entries ride along with a
    // device row through as many reachable/unreachable hops as needed.
    const controls = useRef<ControlStore>(new Map()).current

    useEffect(() => {
        refresh()
        const t = setInterval(refresh, 1000)
        return () => clearInterval(t)
    }, [refresh])

    // The host and gateway are already in the snapshot; role tells them apart.
    // Everything else is a peer, split by the engine's own reachability flag so
    // a blocked-and-unreachable device still falls through to the lower table.
    const host = devices.find((d) => d.role === 'host')
    const gateway = devices.find((d) => d.role === 'gateway')
    const peers = devices.filter((d) => !d.role)
    const reachable = peers.filter((d) => d.reachable)
    const unreachable = peers.filter((d) => !d.reachable)

    return (
        <div className="page">
            <div className="page-header">
                <h2>Devices</h2>
                <p>{peers.length} devices on the current session</p>
            </div>
            {startupError && <div className="error-bar">{startupError}</div>}
            {error && <div className="error-bar">{error}</div>}
            <div className="session-totals">
                <span><span className="muted">Sent</span> {totals.sent || '—'}</span>
                <span><span className="muted">Received</span> {totals.received || '—'}</span>
            </div>
            <TopologyTable host={host} gateway={gateway} />
            <div className="section-head">
                <h3>Devices</h3>
                <span className="count">{reachable.length}</span>
            </div>
            <DeviceTable
                devices={reachable}
                controls={controls}
                empty="No reachable devices yet."
                onError={setError}
                onChanged={refresh}
            />
            <div className="section-head">
                <h3>Unreachable</h3>
                <span className="count">{unreachable.length}</span>
            </div>
            <DeviceTable
                devices={unreachable}
                controls={controls}
                empty="No unreachable devices."
                onError={setError}
                onChanged={refresh}
                className="unreachable-wrap"
            />
        </div>
    )
}

function PlaceholderPage({ title }: { title: string }) {
    return (
        <div className="page placeholder">
            <h2>{title}</h2>
            <p>This page is ready for the next feature.</p>
        </div>
    )
}

export default function App() {
    const page: Page = 'devices'
    const [iface, setIface] = useState<string>('')
    const [ipfwd, setIpfwd] = useState<boolean>(false)
    const [ifaceFwd, setIfaceFwd] = useState<boolean>(false)

    useEffect(() => {
        GetIface().then(setIface)
        GetIpfwd().then(setIpfwd)
        GetIfacefwd().then(setIfaceFwd)
    }, [])

    return (
        <div className="app-shell">
            <header className="topbar">
                <div>
                    <strong>fmmon</strong>
                    <span className="muted"> / network monitor</span>
                </div>
                <div className="topbar-right">
                    <span className="pill">iface: {iface}</span>
                    <span className="pill">ipfwd: {ipfwd ? 'on' : 'off'}</span>
                    <span className="pill">ifacefwd: {ifaceFwd ? 'on' : 'off'}</span>
                </div>
            </header>
            <div className="app-body">
                <main className="content">
                    {(() => {
                        const pages: Record<Page, ReactNode> = {
                            devices: <DevicesPage />,
                            activity: <PlaceholderPage title="Activity" />,
                            rules: <PlaceholderPage title="Rules" />,
                            settings: <PlaceholderPage title="Settings" />,
                        }
                        return pages[page]
                    })()}
                </main>
            </div>
        </div>
    )
}
