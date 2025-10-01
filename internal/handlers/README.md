# Handlers

This package contains the HTTP and WebSocket request handlers that expose agent functionality. Handlers follow a controller-style pattern built on the shared `BaseHandler`, which wires logging, configuration, and service access.

## Structure

- `database_handler.go` – Groups database related commands.
- `command_handler.go` – Aggregates command execution and listing.
- `monitoring_handlers.go` – Exposes status, metrics, and alert management actions.
- `update_handler.go` – Handles agent update checks and application.

Legacy single-command handlers remain as empty stubs and are marked `Deprecated`. They are kept only to preserve build continuity while downstream code migrates. Avoid adding new logic there.

## Adding a new handler

1. Create a new file alongside the existing controllers.
2. Define a struct embedding `*BaseHandler` and a `Register` function that mounts routes via the provided router.
3. Add handler methods. Each should:
   - Log the incoming request context.
   - Use `h.services` to fetch the required service.
   - Validate and decode payloads.
   - Return structured responses or errors via the route helper.
4. Export the handler’s `Register` function from `routes.RegisterAll` for automatic wiring.

Keep business logic within services. Handlers should validate input, invoke services, and translate results into responses.
