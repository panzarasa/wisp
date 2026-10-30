package wisp

// Content types for responses, ready to pass to Ctx.Bytes and Ctx.String.
// Text types carry charset=utf-8; JSON needs none (RFC 8259 makes it UTF-8).
const (
	MIMETextPlain      = "text/plain; charset=utf-8"
	MIMETextHTML       = "text/html; charset=utf-8"
	MIMETextCSS        = "text/css; charset=utf-8"
	MIMETextCSV        = "text/csv; charset=utf-8"
	MIMETextJavaScript = "text/javascript; charset=utf-8"

	MIMEApplicationJSON = "application/json"
	MIMEApplicationXML  = "application/xml; charset=utf-8"
	MIMEApplicationForm = "application/x-www-form-urlencoded"
	MIMEApplicationPDF  = "application/pdf"
	MIMEOctetStream     = "application/octet-stream"
	MIMEMultipartForm   = "multipart/form-data"

	MIMEImagePNG  = "image/png"
	MIMEImageJPEG = "image/jpeg"
	MIMEImageGIF  = "image/gif"
	MIMEImageWebP = "image/webp"
	MIMEImageSVG  = "image/svg+xml"
	MIMEImageICO  = "image/x-icon"
)
