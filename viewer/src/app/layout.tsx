import type { Metadata } from "next"
import "./globals.css"
import { DataProvider } from "@/hooks/use-data"

export const metadata: Metadata = {
  title: "Bloodyomain — AD Attack Path Report",
  description: "Advanced Active Directory security audit report",
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>
        <DataProvider>
          {children}
        </DataProvider>
      </body>
    </html>
  )
}
