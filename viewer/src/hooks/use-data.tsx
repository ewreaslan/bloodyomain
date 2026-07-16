"use client"

import { createContext, useContext, useEffect, useState, type ReactNode } from "react"
import { getEmptyData, loadData } from "@/lib/data"
import type { ADData } from "@/lib/types"

const DataContext = createContext<{ data: ADData; loading: boolean; error: string | null }>({
  data: getEmptyData(),
  loading: true,
  error: null,
})

export function DataProvider({ children }: { children: ReactNode }) {
  const [data, setData] = useState<ADData>(getEmptyData())
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    loadData()
      .then(d => { setData(d); setLoading(false) })
      .catch(e => { setError(e.message); setLoading(false) })
  }, [])

  return (
    <DataContext.Provider value={{ data, loading, error }}>
      {children}
    </DataContext.Provider>
  )
}

export function useData() {
  return useContext(DataContext)
}
