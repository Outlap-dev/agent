package routes

import (
	"fmt"

	"outlap-agent-go/internal/handlers"
	"outlap-agent-go/pkg/logger"
)

// Router is the main entry point for route registration.
// It provides an Echo-style fluent API for organizing handlers.
type Router struct {
	registry *handlers.Registry
	logger   *logger.Logger
}

// Container abstracts the minimal data required to register routes.
type Container interface {
	HandlerRegistry() *handlers.Registry
	BaseLogger() *logger.Logger
	APIBaseURL() string
}

// NewRouter creates a new router for registering handlers.
func NewRouter(registry *handlers.Registry, logger *logger.Logger) *Router {
	return &Router{
		registry: registry,
		logger:   logger.With("component", "router"),
	}
}

// Group creates a new route group with the given prefix.
// Groups allow you to organize related routes under a common namespace.
func (r *Router) Group(prefix string) *Group {
	return &Group{
		router: r,
		prefix: prefix,
	}
}

// Group represents a collection of routes under a common prefix.
// It supports nesting via the Group() method for hierarchical organization.
type Group struct {
	router *Router
	prefix string
}

// Group creates a nested group under the current group's prefix.
func (g *Group) Group(prefix string) *Group {
	return &Group{
		router: g.router,
		prefix: g.buildPath(prefix),
	}
}

// Controller creates a nested group scoped to the provided controller, enabling
// Echo-style route registration where individual controller methods are bound
// with minimal ceremony.
func (g *Group) Controller(prefix string, controller handlers.Controller) *ControllerGroup {
	if controller == nil {
		g.router.logger.Warn("attempted to create controller group with nil controller", "prefix", g.buildPath(prefix))
	}

	subgroup := g
	if prefix != "" {
		subgroup = g.Group(prefix)
	}

	return &ControllerGroup{
		group:      subgroup,
		controller: controller,
	}
}

// Route defines a new route with the given path.
// Returns a RouteBuilder for fluent handler registration.
func (g *Group) Route(path string) *RouteBuilder {
	return &RouteBuilder{
		group:   g,
		path:    path,
		command: g.buildPath(path),
	}
}

// buildPath constructs the full command path by joining the group prefix with the given path.
func (g *Group) buildPath(path string) string {
	if g.prefix == "" {
		return path
	}
	if path == "" {
		return g.prefix
	}
	return g.prefix + "." + path
}

// RouteBuilder provides a fluent interface for registering handlers.
type RouteBuilder struct {
	group   *Group
	path    string
	command string
}

// Handler registers the given handler for this route.
// The handler will be assigned the route's command and added to the registry.
func (rb *RouteBuilder) Handler(handler handlers.Handler) {
	if handler == nil {
		rb.group.router.logger.Warn("attempted to register nil handler", "command", rb.command)
		return
	}

	// Set the command on the handler if it supports it
	if setter, ok := handler.(commandSetter); ok {
		setter.SetCommand(rb.command)
	} else {
		rb.group.router.logger.Warn(
			"handler does not support command assignment",
			"command", rb.command,
			"handler", fmt.Sprintf("%T", handler),
		)
	}

	rb.group.router.registry.Register(handler)
	rb.group.router.logger.Debug("registered route", "command", rb.command, "handler", fmt.Sprintf("%T", handler))
}

// HandlerFunc registers a controller method for this route, adapting it to the
// Handler interface automatically.
func (rb *RouteBuilder) HandlerFunc(controller handlers.Controller, fn handlers.CommandFunc) {
	if controller == nil {
		rb.group.router.logger.Warn("attempted to register controller function with nil controller", "command", rb.command)
		return
	}

	if fn == nil {
		rb.group.router.logger.Warn("attempted to register nil controller function", "command", rb.command)
		return
	}

	handler := handlers.NewMethodHandler(controller.Base(), fn)
	if handler == nil {
		rb.group.router.logger.Warn("failed to adapt controller function", "command", rb.command)
		return
	}

	rb.Handler(handler)
}

// commandSetter is the interface for handlers that support external command assignment.
type commandSetter interface {
	SetCommand(string)
}

// ControllerGroup provides a fluent builder for registering controller methods
// within a route group.
type ControllerGroup struct {
	group      *Group
	controller handlers.Controller
}

// Handle registers a controller method for the given path and returns the
// controller group for fluent chaining.
func (cg *ControllerGroup) Handle(path string, fn handlers.CommandFunc) *ControllerGroup {
	if cg == nil {
		return nil
	}

	cg.group.Route(path).HandlerFunc(cg.controller, fn)
	return cg
}

// Route is an alias for Handle to mirror the RouteBuilder terminology.
func (cg *ControllerGroup) Route(path string, fn handlers.CommandFunc) *ControllerGroup {
	return cg.Handle(path, fn)
}

// RegisterAll registers all application routes.
func RegisterAll(container Container, services handlers.ServiceProvider) {
	if container == nil {
		return
	}

	registry := container.HandlerRegistry()
	handlerLogger := container.BaseLogger()

	if registry == nil || handlerLogger == nil {
		return
	}

	router := NewRouter(registry, handlerLogger)

	RegisterDatabaseRoutes(router, handlerLogger, services, &DatabaseRouteConfig{
		APIBaseURL: container.APIBaseURL(),
	})
	RegisterServiceRoutes(router, handlerLogger, services)
	RegisterAgentRoutes(router, handlerLogger, services)
	RegisterServerRoutes(router, handlerLogger, services)
	RegisterMonitoringRoutes(router, handlerLogger, services)
	RegisterCaddyRoutes(router, handlerLogger, services)
}
