import { Card, Title, Text } from "@tremor/react";
import ProvidersTable from "./table";
import { getServerSession } from "../../utils/customAuth";
import { getApiURL } from "../../utils/apiUrl";

export default async function ProvidersPage() {
  console.log("Rendering dashboard page");
  // get the session so we will be able to pass it to the SessionProvider
  const session = await getServerSession();
  // force get session to get a token
  const accessToken = (
    await getServerSession({
      callbacks: { session: ({ token }) => token },
    })
  )?.accessToken;

  let installed_providers = [];
  // Now let's fetch the providers status from the backend
  try {
    const apiUrl = getApiURL();
    installed_providers = await fetch(`${apiUrl}/providers`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    }).then((res) => res.json());
  } catch (err) {
    console.log("Error fetching providers status", err);
    if (err instanceof Error) {
      return <div>Error: {err.message}</div>;
    }
    return <div>502 backend error</div>;
  }

  console.log("Dashboard | session:", session);
  return (
    <main className="p-4 md:p-10 mx-auto max-w-7xl">
      <Title>Providers</Title>
      <Text>Connect providers to Keep to make your alerts better.</Text>
      <Card className="mt-6">
        <ProvidersTable installed_providers={installed_providers} />
      </Card>
    </main>
  );
}
