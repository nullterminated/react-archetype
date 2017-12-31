#set( $symbol_pound = '#' )
#set( $symbol_dollar = '$' )
#set( $symbol_escape = '\' )
package ${package};

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketClose;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketConnect;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketError;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketMessage;
import org.eclipse.jetty.websocket.api.annotations.WebSocket;

@WebSocket
public class MyWebSocket {
	private static final Logger LOG = LogManager.getLogger(MyWebSocket.class);

	@OnWebSocketClose
	public void onClose(final Session session, final int statusCode, final String reason) {
		LOG.info("Close: statusCode=" + statusCode + ", reason=" + reason);
	}

	@OnWebSocketConnect
	public void onConnect(final Session session) {
		LOG.info("Connect: " + session.getRemoteAddress().getAddress());
		try {
			session.getRemote().sendString("Hello Webbrowser");
		} catch (final IOException e) {
			e.printStackTrace();
		}
	}

	@OnWebSocketError
	public void onError(final Session session, final Throwable t) {
		LOG.info("Error: " + t.getMessage());
	}

	@OnWebSocketMessage
	public void onMessage(final Session session, final String message) {
		LOG.info("Message: " + message);
	}

}
