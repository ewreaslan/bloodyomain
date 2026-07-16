import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function escapeHtml(s: string | null | undefined): string {
  if (s === null || s === undefined) return ""
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
}

export function formatDate(iso: string): string {
  const d = new Date(iso)
  return isNaN(d.getTime()) ? iso : d.toLocaleString()
}

export function severityColor(sev: string): string {
  switch (sev) {
    case "CRITICAL": return "text-accent-red"
    case "HIGH": return "text-accent-orange"
    case "MEDIUM": return "text-accent-yellow"
    case "LOW": return "text-text-muted"
    default: return "text-accent-blue"
  }
}

export function severityBg(sev: string): string {
  switch (sev) {
    case "CRITICAL": return "bg-red-500/10 border-red-500/30 text-red-400"
    case "HIGH": return "bg-orange-500/10 border-orange-500/30 text-orange-400"
    case "MEDIUM": return "bg-yellow-500/10 border-yellow-500/30 text-yellow-400"
    default: return "bg-blue-500/10 border-blue-500/30 text-blue-400"
  }
}
