"use client"

export function LoadingSkeleton() {
  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center space-y-4">
        <div className="w-3 h-3 rounded-full bg-accent-red mx-auto animate-pulse-glow shadow-red-500" />
        <p className="text-text-secondary font-mono text-sm animate-pulse">Loading report data...</p>
      </div>
    </div>
  )
}
