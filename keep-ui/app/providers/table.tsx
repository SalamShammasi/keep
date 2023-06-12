'use client';
import React from "react";
import { Table } from "@tremor/react";
import ProviderRow from "./provider-row";
import { SessionProvider } from "next-auth/react";
import { Session } from "next-auth";
import { Providers } from "./providers";

const isSingleTenant = process.env.NEXT_PUBLIC_AUTH_ENABLED === "false";

export default function ProvidersTable({
  session,
  providers,
}: {
  session: Session | null;
  providers: Providers;
}) {

  return (
    <Table>
      <tbody>
        {isSingleTenant ? (
          providers.filter((provider) => Object.keys(provider.details).length > 0)
            .map((provider) => (
              <ProviderRow provider={provider} />
            ))
        ) : (
          <SessionProvider session={session}>
            {providers.filter((provider) => Object.keys(provider.details).length > 0)
            .map((provider) => (
              <ProviderRow provider={provider} />
            ))}
          </SessionProvider>
        )}
      </tbody>
    </Table>
  );




}
