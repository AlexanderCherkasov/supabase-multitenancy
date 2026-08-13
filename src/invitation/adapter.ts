/**
 * Server-only invitation adapter.
 * Core package never sends email itself; consumer provides an implementation.
 * Raw tokens must never be persisted to logs or audit.
 */

export interface SendInvitationInput {
  email: string;
  acceptUrl: string;
  tenantName: string;
  inviterName?: string;
  expiresAt: string; // ISO 8601
}

export interface InvitationSender {
  sendInvitation(input: SendInvitationInput): Promise<void>;
}

/**
 * Build the accept URL for an invitation.
 * Keep token in query or path per consumer routing.
 */
export function buildAcceptUrl(baseUrl: string, token: string): string {
  const url = new URL(baseUrl);
  url.searchParams.set("token", token);
  return url.toString();
}

/**
 * Example server-only helper to be called from a Supabase Edge Function or
 * server route after `invitations.create` RPC returns a raw token.
 * The token is passed only here and never stored.
 *
 * @example
 * const { token, expires_at } = await mt.invitations.create(tenantId, { email, grants })
 * await deliverInvitation({ email, tenantName, token, expiresAt: expires_at, baseAcceptUrl, sender })
 */
export async function deliverInvitation(opts: {
  email: string;
  tenantName: string;
  token: string;
  expiresAt: string;
  baseAcceptUrl: string;
  inviterName?: string;
  sender: InvitationSender;
}): Promise<void> {
  const acceptUrl = buildAcceptUrl(opts.baseAcceptUrl, opts.token);
  await opts.sender.sendInvitation({
    email: opts.email,
    acceptUrl,
    tenantName: opts.tenantName,
    inviterName: opts.inviterName,
    expiresAt: opts.expiresAt,
  });
  // Explicitly avoid logging raw token
}
