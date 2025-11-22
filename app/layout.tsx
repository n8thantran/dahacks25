import './globals.css'

export const metadata = {
  title: 'Meridian Trust Bank - Online Banking',
  description: 'Secure online banking with Meridian Trust Bank',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
