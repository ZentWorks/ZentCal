package audit

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Logger struct{ DB *pgxpool.Pool }

const RetentionDays = 60

func (l *Logger) Cleanup(ctx context.Context) error {
	_, err := l.DB.Exec(ctx, `DELETE FROM audit_logs WHERE created_at < now() - ($1::int * interval '1 day')`, RetentionDays)
	return err
}

func (l *Logger) Write(ctx context.Context, r *http.Request, actorID, action, resourceType, resourceID string, details any) {
	b, _ := json.Marshal(details)
	if len(b) == 0 {
		b = []byte(`{}`)
	}
	ip := ""
	ua := ""
	reqID := ""
	if r != nil {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil {
			ip = host
		} else {
			ip = strings.Trim(r.RemoteAddr, "[]")
		}
		ua = r.UserAgent()
		reqID = r.Header.Get("X-Request-ID")
	}
	var actor any = nil
	if actorID != "" {
		actor = actorID
	}
	_, _ = l.DB.Exec(ctx, `INSERT INTO audit_logs(actor_user_id,action,resource_type,resource_id,details,ip,user_agent,request_id) VALUES($1,$2,$3,$4,$5,NULLIF($6,'')::inet,$7,$8)`, actor, action, resourceType, resourceID, b, ip, ua, reqID)
}
