import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { GetDevices, SetBlocked, SetRateLimit, Status } from '../bindings/github.com/saif/spoofer/deviceservice'
import type { DeviceView } from '../bindings/github.com/saif/spoofer/models'

type Page = 'devices' | 'activity' | 'rules' | 'settings'

type Unit = 'kb' | 'mb' | 'gb'

// Decimal, matching formatRate: 1 kb = 1000 bytes.
const unitToKb: Record<Unit, number> = { kb: 1, mb: 1000, gb: 1000 * 1000 }

type Direction = 'up' | 'down'

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

function DeviceControls({ device, onError, onChanged }: {
    device: DeviceView
    onError: (msg: string) => void
    onChanged: () => Promise<void>
}) {
    const [up, setUp] = useState('')
    const [down, setDown] = useState('')
    const [upUnit, setUpUnit] = useState<Unit>('kb')
    const [downUnit, setDownUnit] = useState<Unit>('kb')

    // The engine owns the truth. pending only covers the window between the
    // click and the call settling, then drops back to null so the checkbox
    // renders whatever the engine actually reports - including rolling itself
    // back when the call failed.
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
    // at the cap already in force rather than reading as 0.
    const seeded = useRef(false)
    useEffect(() => {
        if (seeded.current) return
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
        if (upKB > 0 || downKB > 0) seeded.current = true
    }, [device.upLimitKB, device.downLimitKB])

    // Last value handed to the engine per direction, so an edit that lands back on
    // what is already applied sends nothing. null until the first send.
    const applied = useRef<Record<Direction, number | null>>({ up: null, down: null })
    const timers = useRef<Record<Direction, number>>({ up: 0, down: 0 })

    async function sendLimit(dir: Direction, raw: string, unit: Unit) {
        // The engine wants kb/s as a plain number; a blank box reads as 0,
        // which the engine takes as "clear this".
        const rate = (Number(raw) || 0) * unitToKb[unit]
        if (applied.current[dir] === rate) return
        try {
            await SetRateLimit(device.ip, dir, rate)
            // Only on success, so a failed edit is retried rather than
            // remembered as already in force.
            applied.current[dir] = rate
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

    useEffect(() => () => {
        window.clearTimeout(timers.current.up)
        window.clearTimeout(timers.current.down)
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

function DevicesPage() {
    const [devices, setDevices] = useState<DeviceView[]>([])
    const [error, setError] = useState('')
    const [startupError, setStartupError] = useState('')

    // Shared by the 1s poll and the block toggle, so a toggle does not sit
    // waiting a full tick for the engine's answer.
    const refresh = useCallback(async () => {
        const [result, status] = await Promise.all([GetDevices(), Status()])
        setDevices(result ?? [])
        setStartupError(status?.error ?? '')
    }, [])

    useEffect(() => {
        refresh()
        const t = setInterval(refresh, 1000)
        return () => clearInterval(t)
    }, [refresh])
    return (
        <div className="page">
            <div className="page-header">
                <h2>Devices</h2>
                <p>{devices.length} devices on the current session</p>
            </div>
            {startupError && <div className="error-bar">{startupError}</div>}
            {error && <div className="error-bar">{error}</div>}
            <div className="table-wrap">
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
                            <th>Controls</th>
                        </tr>
                    </thead>
                    <tbody>
                        {devices.map((d) => (
                            <tr key={d.ip}>
                                <td>{d.name}</td>
                                <td>{d.ip}</td>
                                <td>{d.mac}</td>
                                <td>{d.vendor}</td>
                                <td className="rate-cell">
                                    {d.upRate}
                                    {d.upLimit && <span className="limit-note">cap {d.upLimit}</span>}
                                </td>
                                <td className="rate-cell">
                                    {d.downRate}
                                    {d.downLimit && <span className="limit-note">cap {d.downLimit}</span>}
                                </td>
                                <td>
                                    <div className="badges">
                                        {(d.state ?? []).map((s) => (
                                            <span key={s} className={`badge badge-${s}`}>{s}</span>
                                        ))}
                                    </div>
                                </td>
                                <td className="controls-col"><DeviceControls device={d} onError={setError} onChanged={refresh} /></td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
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

    return (
        <div className="app-shell">
            <header className="topbar">
                <div>
                    <strong>fmmon</strong>
                    <span className="muted"> / network monitor</span>
                </div>
                <div className="topbar-right">
                    <span className="pill">iface: enp0s31f6</span>
                    <span className="pill">ipfwd: on</span>
                    <span className="pill">tc: active</span>
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
