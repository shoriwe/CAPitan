package base

import (
	"bytes"
	"html/template"
)

var baseTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{.Title}}</title>
</head>
<body>
{{.Dashboard}}
{{.Body}}
</body>
</html>`

func NewPage(title, dashboard, body string) string {
	var output bytes.Buffer
	t := template.Must(template.New("page").Parse(baseTemplate))
	_ = t.Execute(
		&output,
		struct {
			Title     string
			Dashboard template.HTML
			Body      template.HTML
		}{
			Title:     title,
			Dashboard: template.HTML(dashboard),
			Body:      template.HTML(body),
		},
	)
	return output.String()
}
