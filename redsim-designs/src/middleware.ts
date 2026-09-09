import { NextResponse, type NextRequest } from "next/server"
import { parseSession, SESSION_COOKIE } from "@/lib/session-cookie"

/**
 * Server-side auth guard. Runs before the page renders, so there is never a
 * client-side redirect bounce or a full-page spinner while a session loads.
 */
export function middleware(req: NextRequest) {
  const session = parseSession(req.cookies.get(SESSION_COOKIE)?.value)
  const { pathname } = req.nextUrl
  const isLogin = pathname === "/login"

  if (!session && !isLogin) {
    const url = req.nextUrl.clone()
    url.pathname = "/login"
    return NextResponse.redirect(url)
  }
  if (session && isLogin) {
    const url = req.nextUrl.clone()
    url.pathname = "/dashboard"
    return NextResponse.redirect(url)
  }
  return NextResponse.next()
}

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],
}
