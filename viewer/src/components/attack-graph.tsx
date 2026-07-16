"use client"

import { useEffect, useRef, useState, useCallback } from "react"
import * as d3 from "d3"
import { Maximize2, Eye, EyeOff, AlertTriangle } from "lucide-react"
import { ADData } from "@/lib/types"

export function AttackGraph({ data, daSet }: { data: ADData; daSet: Set<string> }) {
  const svgRef = useRef<SVGSVGElement>(null)
  const [showLabels, setShowLabels] = useState(true)
  const [dangerOnly, setDangerOnly] = useState(false)
  const [info, setInfo] = useState<{ id: string; rows: [string, string][] } | null>(null)
  const simRef = useRef<any>(null)

  const initGraph = useCallback(() => {
    const svg = d3.select(svgRef.current!)
    svg.selectAll("*").remove()
    const W = svg.node()!.clientWidth, H = svg.node()!.clientHeight
    if (!W || !H) return

    const g = svg.append("g")
    svg.call(d3.zoom<any, unknown>().scaleExtent([0.1, 5]).on("zoom", e => g.attr("transform", e.transform)))

    const nodeMap: Record<string, any> = {}
    ;(data.graph_nodes || []).forEach(n => {
      nodeMap[n.id] = { ...n, x: W/2 + (Math.random() - 0.5) * 400, y: H/2 + (Math.random() - 0.5) * 300 }
    })
    const edges = (data.edges || []).map(e => ({ ...e }))
    edges.forEach(e => {
      if (!nodeMap[e.source]) nodeMap[e.source] = { id: e.source, type: "user", x: W/2, y: H/2 }
      if (!nodeMap[e.target]) nodeMap[e.target] = { id: e.target, type: "user", x: W/2, y: H/2 }
    })
    const nodes: any[] = Object.values(nodeMap)

    const NC: Record<string, string> = { user: "#3b82f6", group: "#8b5cf6", computer: "#22c55e", attack: "#ef4444", dc: "#eab308" }
    const nColor = (n: any) => n.is_dc ? NC.dc : NC[n.type] || "#64748b"
    const nR = (n: any) => {
      if (n.type === "attack") return 20; if (n.is_dc) return 18
      if (n.admin || daSet.has((n.id || "").toUpperCase())) return 16; return 10
    }
    const lColor = (e: any) => {
      if (e.color) return e.color
      if (e.relation === "HasSession") return "#ef4444"; if (e.relation === "CanRDP") return "#8b5cf6"
      if (e.relation === "LocalAdmin") return "#f59e0b"; if (e.relation === "MemberOf") return "#374151"
      return "#1e2d3d"
    }

    const defs = svg.append("defs");
    ["red", "orange", "purple", "gray"].forEach(id => {
      const clr: Record<string, string> = { red: "#ef4444", orange: "#f59e0b", purple: "#8b5cf6", gray: "#374151" }
      defs.append("marker").attr("id", `arr-${id}`).attr("viewBox", "0 -4 8 8")
        .attr("refX", 22).attr("refY", 0).attr("markerWidth", 5).attr("markerHeight", 5).attr("orient", "auto")
        .append("path").attr("d", "M0,-4L8,0L0,4").attr("fill", clr[id])
    })
    const arrowId = (e: any) => {
      const c = lColor(e); if (c === "#ef4444") return "arr-red"
      if (c === "#f59e0b") return "arr-orange"; if (c === "#8b5cf6") return "arr-purple"; return "arr-gray"
    }

    const sim = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(edges).id((d: any) => d.id).distance((d: any) => d.relation === "HasSession" ? 60 : 90).strength(0.5))
      .force("charge", d3.forceManyBody().strength(-220))
      .force("center", d3.forceCenter(W/2, H/2))
      .force("collision", d3.forceCollide().radius((d: any) => nR(d) + 10))
    simRef.current = sim

    const linkSel = g.append("g").selectAll("line").data(edges).join("line")
      .attr("class", (e: any) => "link" + (e.highlight ? " hl" : ""))
      .attr("stroke", lColor)
      .attr("stroke-dasharray", (e: any) => e.relation === "HasSession" ? "5,3" : null)
      .attr("marker-end", (e: any) => `url(#${arrowId(e)})`)

    const nodeSel = g.append("g").selectAll("g").data(nodes).join("g")
      .attr("class", (d: any) => "node" + ((d.type === "attack" || daSet.has((d.id || "").toUpperCase()) || d.is_dc) ? " crit" : ""))
      .call(d3.drag<any, any>().on("start", (ev, d) => { if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y })
        .on("drag", (ev, d) => { d.fx = ev.x; d.fy = ev.y })
        .on("end", (ev, d) => { if (!ev.active) sim.alphaTarget(0); d.fx = null; d.fy = null }))

    nodeSel.append("circle").attr("r", nR).attr("fill", (d: any) => nColor(d) + "28").attr("stroke", nColor)
    const labelSel = nodeSel.append("text").attr("dy", (d: any) => nR(d) + 12)
      .text((d: any) => d.id.length > 16 ? d.id.slice(0, 15) + "…" : d.id)

    nodeSel.on("click", (ev: any, d: any) => {
      const rows: [string, string][] = [["Type", d.type]]
      if (d.is_dc) rows.push(["Role", "Domain Controller"])
      if (daSet.has((d.id || "").toUpperCase())) rows.push(["Privilege", "Domain Admin"])
      if (d.admin) rows.push(["adminCount", "1 (protected)"])
      if (d.rdp_open) rows.push(["RDP", "Port 3389 open"])
      if (d.delegation) rows.push(["Delegation", "Unconstrained"])
      if (d.spns) rows.push(["SPNs", String(d.spns)])
      if (d.no_preauth) rows.push(["AS-REP", "Roastable"])
      setInfo({ id: d.id, rows })
      ev.stopPropagation()
    })
    svg.on("click", () => setInfo(null))

    sim.on("tick", () => {
      linkSel.attr("x1", (d: any) => d.source.x).attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x).attr("y2", (d: any) => d.target.y)
      nodeSel.attr("transform", (d: any) => `translate(${d.x},${d.y})`)
    })

    // Store refs for filters
    ;(window as any).__graphRefs = { linkSel, nodeSel, labelSel, dangerOnly, showLabels }
  }, [data, daSet])

  useEffect(() => { initGraph() }, [initGraph])

  const applyFilters = useCallback((danger: boolean, labels: boolean) => {
    const refs = (window as any).__graphRefs
    if (!refs) return
    const { linkSel, nodeSel, labelSel } = refs
    linkSel.style("opacity", (e: any) => !danger ? null : e.highlight ? null : "0.04")
    nodeSel.style("opacity", (d: any) => !danger ? 1 : (d.type === "attack" || d.admin || d.is_dc || daSet.has((d.id || "").toUpperCase()) || d.delegation) ? 1 : 0.06)
    labelSel.style("display", labels ? "" : "none")
  }, [daSet])

  return (
    <div className="space-y-3 animate-fade-in">
      <h2 className="text-sm font-bold text-text-primary">Attack Graph — {data.graph_nodes?.length || 0} nodes, {data.edges?.length || 0} edges</h2>
      <div className="glass rounded-xl relative h-[640px] overflow-hidden">
        <div className="absolute top-2.5 right-2.5 flex gap-1 z-10">
          <GraphBtn icon={<Maximize2 className="w-3 h-3" />} label="Reset" onClick={() => { if (simRef.current) simRef.current.alpha(1).restart() }} />
          <GraphBtn icon={showLabels ? <Eye className="w-3 h-3" /> : <EyeOff className="w-3 h-3" />} label="Labels" active={showLabels} onClick={() => { setShowLabels(!showLabels); applyFilters(dangerOnly, !showLabels) }} />
          <GraphBtn icon={<AlertTriangle className="w-3 h-3" />} label="Danger" active={dangerOnly} onClick={() => { setDangerOnly(!dangerOnly); applyFilters(!dangerOnly, showLabels) }} />
        </div>

        {info && (
          <div className="absolute top-2.5 left-2.5 z-10 glass border-accent-cyan/20 rounded-lg px-3 py-2 font-mono text-[11px] min-w-[180px] shadow-[0_0_20px_rgba(0,180,216,0.1)]">
            <div className="text-accent-cyan font-bold text-xs mb-1">{info.id}</div>
            {info.rows.map(([k, v]) => (
              <div key={k} className="flex gap-2 py-px">
                <span className="text-text-muted min-w-[80px]">{k}</span>
                <span className="text-text-primary font-semibold">{v}</span>
              </div>
            ))}
          </div>
        )}

        <svg ref={svgRef} className="w-full h-full" />

        <div className="absolute bottom-2.5 left-2.5 glass rounded-md px-2.5 py-1.5 flex flex-wrap gap-3 text-[10px]">
          {[{ color: "#3b82f6", label: "User" }, { color: "#8b5cf6", label: "Group" }, { color: "#22c55e", label: "Computer" }, { color: "#eab308", label: "DC" }, { color: "#ef4444", label: "Attack" }].map(l => (
            <span key={l.label} className="flex items-center gap-1"><span className="w-2 h-2 rounded-full border-2" style={{ borderColor: l.color, background: l.color + "33" }} />{l.label}</span>
          ))}
          <span className="flex items-center gap-1 ml-1"><svg width="22" height="6"><line x1="0" y1="3" x2="22" y2="3" stroke="#ef4444" strokeWidth="2" strokeDasharray="4,2"/></svg>Session</span>
          <span className="flex items-center gap-1"><svg width="22" height="6"><line x1="0" y1="3" x2="22" y2="3" stroke="#8b5cf6" strokeWidth="1.5"/></svg>RDP</span>
          <span className="flex items-center gap-1"><svg width="22" height="6"><line x1="0" y1="3" x2="22" y2="3" stroke="#f59e0b" strokeWidth="2"/></svg>LocalAdmin</span>
        </div>
      </div>
    </div>
  )
}

function GraphBtn({ icon, label, active, onClick }: { icon: React.ReactNode; label: string; active?: boolean; onClick: () => void }) {
  return (
    <button onClick={onClick} className={`flex items-center gap-1 px-2 py-1.5 text-[10px] font-semibold rounded-md border transition-all ${active ? "border-accent-yellow text-accent-yellow bg-accent-yellow/10" : "border-white/[0.06] text-text-secondary bg-black/50 hover:border-accent-cyan hover:text-accent-cyan"}`}>
      {icon}{label}
    </button>
  )
}
