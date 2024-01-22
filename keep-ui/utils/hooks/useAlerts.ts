import { AlertDto } from "app/alerts/models";
import { useSession } from "next-auth/react";
import Pusher, { Channel } from "pusher-js";
import zlib from "zlib";
import useSWR, { SWRConfiguration } from "swr";
import useSWRSubscription, { SWRSubscriptionOptions } from "swr/subscription";
import { getApiURL } from "utils/apiUrl";
import { fetcher } from "utils/fetcher";
import { useConfig } from "./useConfig";

type AlertSubscription = {
  alerts: AlertDto[];
  lastSubscribedDate: Date;
  isAsyncLoading: boolean;
  pusherChannel: Channel | null;
};

export const getFormatAndMergePusherWithEndpointAlerts = (
  endpointAlerts: AlertDto[],
  pusherAlerts: AlertDto[]
): AlertDto[] => {
  const pusherAlertsWithLastReceivedDate = pusherAlerts.map((pusherAlert) => ({
    ...pusherAlert,
    lastReceived: new Date(pusherAlert.lastReceived),
  }));

  const endpointAlertsWithLastReceivedDate = endpointAlerts.map(
    (endpointAlert) => ({
      ...endpointAlert,
      lastReceived: new Date(endpointAlert.lastReceived),
    })
  );

  // Create a map of the latest received times for the new alerts
  const latestReceivedTimes = new Map(
    pusherAlertsWithLastReceivedDate.map((alert) => [
      alert.fingerprint,
      alert.lastReceived,
    ])
  );

  // Filter out previous alerts if they are already in the new alerts with a more recent lastReceived
  const filteredEndpointAlerts = endpointAlertsWithLastReceivedDate.filter(
    (endpointAlert) => {
      const newAlertReceivedTime = latestReceivedTimes.get(
        endpointAlert.fingerprint
      );

      if (newAlertReceivedTime === undefined) {
        return true;
      }

      return endpointAlert.lastReceived > newAlertReceivedTime;
    }
  );

  // Filter out new alerts if their fingerprint is already in the filtered previous alerts
  const filteredPusherAlerts = pusherAlertsWithLastReceivedDate.filter(
    (pusherAlert) =>
      filteredEndpointAlerts.some(
        (endpointAlert) => endpointAlert.fingerprint !== pusherAlert.fingerprint
      )
  );

  return filteredPusherAlerts.concat(filteredEndpointAlerts);
};

export const getDefaultSubscriptionObj = (
  isAsyncLoading: boolean = false,
  pusherChannel: Channel | null = null
): AlertSubscription => ({
  alerts: [],
  isAsyncLoading,
  lastSubscribedDate: new Date(),
  pusherChannel,
});

export const useAlerts = () => {
  const apiUrl = getApiURL();

  const { data: session } = useSession();
  const { data: configData } = useConfig();

  const useAlertHistory = (
    selectedAlert?: AlertDto,
    options?: SWRConfiguration
  ) => {
    return useSWR<AlertDto[]>(
      () =>
        selectedAlert && session
          ? `${apiUrl}/alerts/${
              selectedAlert.fingerprint
            }/history/?provider_id=${selectedAlert.providerId}&provider_type=${
              selectedAlert.source ? selectedAlert.source[0] : ""
            }`
          : null,
      (url) => fetcher(url, session?.accessToken),
      options
    );
  };

  const useAllAlerts = (options?: SWRConfiguration) => {
    return useSWR<AlertDto[]>(
      () => (configData && session ? "alerts" : null),
      () =>
        fetcher(
          `${apiUrl}/alerts?sync=${
            configData?.PUSHER_DISABLED ? "true" : "false"
          }`,
          session?.accessToken
        ),
      options
    );
  };

  const useAllAlertsWithSubscription = () => {
    return useSWRSubscription(
      () =>
        configData?.PUSHER_DISABLED === false && session ? "alerts" : null,
      (_, { next }: SWRSubscriptionOptions<AlertSubscription, Error>) => {
        if (configData === undefined || session === null) {
          console.log("Pusher disabled");

          return () =>
            next(null, {
              alerts: [],
              isAsyncLoading: false,
              lastSubscribedDate: new Date(),
              pusherChannel: null,
            });
        }

        console.log("Connecting to pusher");
        const pusher = new Pusher(configData.PUSHER_APP_KEY, {
          wsHost: configData.PUSHER_HOST,
          wsPort: configData.PUSHER_PORT,
          forceTLS: false,
          disableStats: true,
          enabledTransports: ["ws", "wss"],
          cluster: configData.PUSHER_CLUSTER || "local",
          channelAuthorization: {
            transport: "ajax",
            endpoint: `${apiUrl}/pusher/auth`,
            headers: {
              Authorization: `Bearer ${session.accessToken!}`,
            },
          },
        });

        const channelName = `private-${session.tenantId}`;
        const pusherChannel = pusher.subscribe(channelName);

        pusherChannel.bind("async-alerts", (base64CompressedAlert: string) => {
          const decompressedAlert = zlib.inflateSync(
            Buffer.from(base64CompressedAlert, "base64")
          );

          const newAlerts: AlertDto[] = JSON.parse(
            new TextDecoder().decode(decompressedAlert)
          );

          next(null, {
            alerts: newAlerts,
            lastSubscribedDate: new Date(),
            isAsyncLoading: false,
            pusherChannel,
          });
        });

        pusherChannel.bind("async-done", () => {
          next(null, (data) => {
            if (data) {
              return { ...data, isAsyncLoading: false };
            }

            return {
              alerts: [],
              lastSubscribedDate: new Date(),
              isAsyncLoading: false,
              pusherChannel,
            };
          });
        });

        // If we don't receive any alert in 10 seconds, we assume that the async process is done (#641)
        setTimeout(() => {
          next(null, (data) => {
            if (data) {
              return { ...data, isAsyncLoading: false };
            }

            return {
              alerts: [],
              lastSubscribedDate: new Date(),
              isAsyncLoading: false,
              pusherChannel,
            };
          });
        }, 10000);

        console.log("Connected to pusher");

        return () => pusher.unsubscribe(channelName);
      }
    );
  };

  return { useAlertHistory, useAllAlerts, useAllAlertsWithSubscription };
};
