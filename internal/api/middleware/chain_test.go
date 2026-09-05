package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// orderHandler records the sequence in which middlewares wrap it. Each
// middleware appends its name before calling next, so the recorded slice is
// the order they ran on the request path.
type orderHandler struct{ order *[]string }

func (o orderHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	*o.order = append(*o.order, "handler")
	w.WriteHeader(http.StatusOK)
}

// orderMW returns a middleware that records name at request time.
func orderMW(name string, order *[]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*order = append(*order, name)
			next.ServeHTTP(w, r)
		})
	}
}

// TestChainOrder asserts Chain applies middlewares outermost-first, i.e. the
// first argument runs first on the request path.
func TestChainOrder(t *testing.T) {
	var order []string
	h := Chain(
		orderMW("m1", &order),
		orderMW("m2", &order),
		orderMW("m3", &order),
	)(orderHandler{order: &order})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))

	want := []string{"m1", "m2", "m3", "handler"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order[%d] = %q, want %q (full: %v)", i, order[i], want[i], order)
		}
	}
}
