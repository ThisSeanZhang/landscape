type WebSocketEventHandler = (event: Event) => void;
type WebSocketMessageHandler = (message: MessageEvent) => void;
type WebSocketErrorHandler = (error: Event) => void;

interface ReconnectingWebSocketOptions {
  reconnectInterval?: number;
  maxRetries?: number;
}

class ReconnectingWebSocket {
  private url: string;
  private protocols?: string | string[];
  private reconnectInterval: number;
  private maxRetries: number;
  private retries: number = 0;
  private ws: WebSocket | null = null;

  public onopen?: WebSocketEventHandler;
  public onclose?: WebSocketEventHandler;
  public onmessage?: WebSocketMessageHandler;
  public onerror?: WebSocketErrorHandler;

  constructor(
    url: string,
    protocols?: string | string[],
    options: ReconnectingWebSocketOptions = {},
  ) {
    this.url = url;
    this.protocols = protocols;
    this.reconnectInterval = options.reconnectInterval || 1000;
    this.maxRetries = options.maxRetries || Infinity;
    this.connect();
  }

  private connect() {
    this.ws = new WebSocket(this.url, this.protocols);

    this.ws.onopen = (event) => {
      this.retries = 0;
      console.log("Connected to WebSocket");
      if (this.onopen) this.onopen(event);
    };

    this.ws.onclose = (event) => {
      if (this.retries < this.maxRetries) {
        console.log(
          `Connection lost. Reconnecting in ${this.reconnectInterval} ms...`,
        );
        setTimeout(() => {
          this.retries++;
          this.connect();
        }, this.reconnectInterval);
      } else {
        console.log("Max retries reached. Could not reconnect.");
        if (this.onclose) this.onclose(event);
      }
    };

    this.ws.onmessage = (message) => {
      if (this.onmessage) this.onmessage(message);
    };

    this.ws.onerror = (error) => {
      if (this.onerror) this.onerror(error);
    };
  }

  public send(data: string | ArrayBufferLike | Blob | ArrayBufferView) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(data as any);
    } else {
      console.log("WebSocket is not open. Cannot send data.");
    }
  }

  public close() {
    if (this.ws) {
      this.ws.close();
    }
  }
}

export function generateValidMAC() {
  let mac = [...Array(6)].map(() =>
    ("0" + Math.floor(Math.random() * 256).toString(16)).slice(-2),
  );
  mac[0] = (
    "0" + ((parseInt(mac[0], 16) & 0b11111110) | 0b00000010).toString(16)
  ).slice(-2);
  return mac.join(":");
}

export function formatMacAddress(mac: string): string {
  return mac.replace(/-/g, ":");
}

export function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function formatRate(bps: number): string {
  if (bps < 1000) return `${bps} bps`;
  if (bps < 1000000) return `${(bps / 1000).toFixed(2)} Kbps`;
  if (bps < 1000000000) return `${(bps / 1000000).toFixed(2)} Mbps`;
  return `${(bps / 1000000000).toFixed(2)} Gbps`;
}

export function formatPackets(pps: number): string {
  if (pps < 1000) return `${pps} pps`;
  return `${(pps / 1000).toFixed(2)} Kpps`;
}

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024)
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function formatCount(count: number): string {
  if (count < 1000) return `${count}`;
  if (count < 1000000) return `${(count / 1000).toFixed(1)} K`;
  return `${(count / 1000000).toFixed(1)} M`;
}
