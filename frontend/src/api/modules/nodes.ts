type ApiEnvelope<T> = {
  success: boolean;
  data: T;
  message?: string;
};

export interface NodeSummaryResponse {
  nodeId: string;
  name: string;
  groupName: string;
  address: string;
  status: string;
  tags: string[];
}

export const nodesApi = {
  async list(): Promise<ApiEnvelope<NodeSummaryResponse[]>> {
    return {
      success: true,
      data: [
        {
          nodeId: "local",
          name: "本地节点",
          groupName: "default",
          address: "127.0.0.1",
          status: "online",
          tags: ["local"],
        },
      ],
    };
  },
};
