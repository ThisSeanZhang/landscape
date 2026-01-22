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
    options: ReconnectingWebSocketOptions = {}
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
          `Connection lost. Reconnecting in ${this.reconnectInterval} ms...`
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
      this.ws.send(data);
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
    ("0" + Math.floor(Math.random() * 256).toString(16)).slice(-2)
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
