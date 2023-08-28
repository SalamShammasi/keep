import { Card, Title, Subtitle } from "@tremor/react";

export default function Layout({ children }: { children: any }) {
  return (
    <>
      <main className="p-4 md:p-10 mx-auto max-w-full">
        <Title>Workflows</Title>
        <Subtitle>
          Automate your alert management with workflows.
        </Subtitle>
        <Card className="mt-10 p-4 md:p-10 mx-auto">{children}</Card>
      </main>
    </>
  );
}
