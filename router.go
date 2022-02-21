package httpapp

import (
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/jwtauth"
)

// NewRouter returns a *chi.Mux router to be used
// when initializing a new http server.
func (m *CartStreamApp) NewRouter() *chi.Mux {
	router := chi.NewRouter()
	router.Use(middleware.RealIP)
	router.Use(middleware.RequestID)
	router.Use(logger.HTTPChiMiddleware())
	router.Use(middleware.Recoverer)
	router.Use(middleware.URLFormat)
	router.Use(getCors().Handler)
	router.Use(middleware.WithValue(httpserver.ServerCtxKey, m.Srv))
	router.Use(middleware.WithValue(awsservice.AwsCtxKey, m.aws))

	if m.Srv.Config.Profiling {
		router.Mount("/debug", middleware.Profiler())
	}

	router.Route("/admin", func(router chi.Router) {
		// unauthenticated routes
		router.Get("/versions", SoftwareVersions)
		router.Post("/notifications", SendNotification) // TODO: authenticate
	})

	router.Route("/users", func(router chi.Router) {
		//authenticated routes
		router.Group(func(router chi.Router) {
			router.Use(auth.CreateJWTVerifier(m.Srv.RS256JWTAuth, false))
			router.Use(auth.CreateGetJwtUser())
			router.Get("/me", usershttp.Me)
		})

	})

	router.Route("/route1", func(router chi.Router) {
		//// authenticated routes
		router.Group(func(router chi.Router) {
			router.Use(auth.CreateJWTVerifier(m.Srv.RS256JWTAuth, m.Srv.Config.RequireMailVerification))
			router.Use(auth.CreateGetJwtUser())
			router.Post("/upload_url", shopshttp.GetUploadURL)
			router.Post("/import_and_approve", shopshttp.ImportShopDataAndApprove)
			router.Post("/give_credits", shopshttp.GiveCredits)
		})
	})

	router.Route("/products", func(router chi.Router) {
		//// authenticated routes
		router.Group(func(router chi.Router) {
			router.Use(auth.CreateJWTVerifier(m.Srv.RS256JWTAuth, m.Srv.Config.RequireMailVerification))
			router.Use(auth.CreateGetJwtUser())
			router.Post("/placement_status", productshttp.SetPlacementStatus)
		})
	})

	return router
}

// return the CORS handler
func getCors() *cors.Cors {
	return cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"*"},
		AllowCredentials: true,
		MaxAge:           86400, // Maximum value not ignored by any of major browsers
	})
}
