# Handler Routes

A clean, Echo-style routing system for organizing command handlers in PulseUp Agent.

## Features

- **Fluent API**: Chain methods for readable route definitions
- **Hierarchical Groups**: Nest groups for organized command namespaces
- **Type-Safe**: Compile-time checking of route configurations
- **Clear Structure**: Visual grouping with braces for easy scanning

## Usage

### Basic Route Registration

```go
// Create a router
router := routes.NewRouter(registry, logger)

// Register a simple route
router.Group("service").Route("start").Handler(
    handlers.NewStartServiceHandler(logger, services),
)
```

### Hierarchical Groups

```go
// Create nested groups for organized namespaces
service := router.Group("service")
{
    // Application routes: service.app.*
    app := service.Group("app")
    {
        app.Route("deploy").Handler(handlers.NewDeployApplicationHandler(logger, services))
        app.Route("install").Handler(handlers.NewAppInstallationHandler(logger, services))
    }
    
    // Log routes: service.logs.*
    logs := service.Group("logs")
    {
        logs.Route("fetch").Handler(handlers.NewGetServiceLogsHandler(logger, services))
        logs.Route("stream.start").Handler(sessionHandler)
    }
    
    // Service lifecycle: service.{action}
    service.Route("start").Handler(handlers.NewStartServiceHandler(logger, services))
    service.Route("stop").Handler(handlers.NewStopServiceHandler(logger, services))
    service.Route("restart").Handler(handlers.NewRestartServiceHandler(logger, services))
}
```

### Shared Handler State

When handlers need to share state (like streaming sessions):

```go
logs := service.Group("logs")
{
    // Create the session handler once
    sessionHandler := handlers.NewStreamContainerLogsHandler(logger, services)
    
    // Use it in multiple routes
    logs.Route("stream.start").Handler(sessionHandler)
    logs.Route("stream.stop").Handler(
        handlers.NewStopStreamContainerLogsHandler(logger, services, sessionHandler),
    )
}
```

## Architecture

### Router
The main entry point that holds the registry and logger. Create one router per application.

### Group
Represents a command namespace prefix. Groups can be nested to create hierarchical command structures.

### Route
Defines a specific command path and registers a handler. The full command is built from the group hierarchy.

### Command Naming

Commands are built automatically from the group hierarchy:

```go
router.Group("service").Route("start")
// → Command: "service.start"

router.Group("service").Group("logs").Route("fetch")
// → Command: "service.logs.fetch"

router.Group("service").Group("app").Route("deploy")
// → Command: "service.app.deploy"
```

## Adding New Routes

To add a new route group:

1. Create a new file in `internal/handlers/routes/` (e.g., `database.go`)
2. Define a registration function:

```go
func RegisterDatabaseRoutes(router *Router, logger *logger.Logger, services handlers.ServiceProvider, cfg *DatabaseRouteConfig) {
    controller := handlers.NewDatabaseHandler(logger, services, cfg.AgentToken, cfg.APIBaseURL)

    db := router.Group("database")
    {
        db.Controller("", controller).
            Handle("deploy", controller.Deploy)

        db.Controller("logs", controller).
            Handle("fetch", controller.Logs)

        backups := db.Group("backup")
        {
            backups.Controller("", controller).
                Handle("create", controller.Backup).
                Handle("list", controller.ListBackups).
                Handle("restore", controller.Restore).
                Handle("download", controller.DownloadBackup)

            backups.Controller("automation", controller).
                Handle("update", controller.UpdateAutomation)
        }
    }
}
```

3. Register it in `RegisterAll()`:

```go
func RegisterAll(container Container, services handlers.ServiceProvider) {
    router := NewRouter(container.HandlerRegistry(), container.BaseLogger())

    RegisterDatabaseRoutes(router, container.BaseLogger(), services, &DatabaseRouteConfig{
        AgentToken: container.AgentToken(),
        APIBaseURL: container.APIBaseURL(),
    })
    RegisterServiceRoutes(router, container.BaseLogger(), services)
}
```

## Benefits

- **Readability**: The visual structure matches the command hierarchy
- **Maintainability**: Easy to find and modify routes
- **Scalability**: Add new groups without touching existing code
- **Discoverability**: Clear at a glance what commands exist
- **Type Safety**: Compiler catches missing handlers or wrong types

## Example: Full Service Routes

```go
func RegisterServiceRoutes(router *Router, logger *logger.Logger, services handlers.ServiceProvider) {
    service := router.Group("service")
    {
        // Application deployment
        app := service.Group("app")
        {
            app.Route("deploy").Handler(handlers.NewDeployApplicationHandler(logger, services))
            app.Route("install").Handler(handlers.NewAppInstallationHandler(logger, services))
        }

        // Deployment management
        deploy := service.Group("deploy")
        {
            deploy.Route("rollback").Handler(handlers.NewAppDeploymentRollbackHandler(logger, services))
            deploy.Route("logs.fetch").Handler(handlers.NewDeploymentLogsHandler(logger, services))
        }

        // Log management
        logs := service.Group("logs")
        {
            sessionHandler := handlers.NewStreamContainerLogsHandler(logger, services)
            logs.Route("stream.start").Handler(sessionHandler)
            logs.Route("stream.stop").Handler(handlers.NewStopStreamContainerLogsHandler(logger, services, sessionHandler))
            logs.Route("fetch").Handler(handlers.NewGetServiceLogsHandler(logger, services))
        }

        // Container monitoring
        container := service.Group("container")
        {
            container.Route("stats.live").Handler(handlers.NewContainerStatsHandler(logger, services))
        }

        // Service lifecycle
        service.Route("start").Handler(handlers.NewStartServiceHandler(logger, services))
        service.Route("stop").Handler(handlers.NewStopServiceHandler(logger, services))
        service.Route("restart").Handler(handlers.NewRestartServiceHandler(logger, services))
        service.Route("delete").Handler(handlers.NewServiceDeletionHandler(logger, services))
    service.Route("status.get").Handler(handlers.NewServiceStatusHandler(logger, services))
    }
}
```
