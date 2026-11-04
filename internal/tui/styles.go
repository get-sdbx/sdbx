// Package tui provides TUI components and styles for sdbx.
package tui

import (
	"fmt"
	"strings"
	"unicode"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/compat"
)

// Render applies the terminal's output profile before styled text reaches
// tables or ordinary stdout writers. Lip Gloss v2 renders ANSI unconditionally.
func Render(style lipgloss.Style, values ...string) string {
	return lipgloss.Sprint(style.Render(values...))
}

// Color palette adapts to light and dark terminal backgrounds. The semantic
// roles mirror the website and Web UI: violet carries identity, cyan signals
// healthy or active state, blue carries information, and magenta is reserved
// for rare high-energy labels. Every text color meets a 4.5:1 contrast ratio
// against its corresponding background.
var (
	ColorIdentity = compat.AdaptiveColor{Light: lipgloss.Color("#5B21B6"), Dark: lipgloss.Color("#B78CFF")}
	ColorSignal   = compat.AdaptiveColor{Light: lipgloss.Color("#006377"), Dark: lipgloss.Color("#4DEAFF")}
	ColorBlue     = compat.AdaptiveColor{Light: lipgloss.Color("#2446B8"), Dark: lipgloss.Color("#9BAEFF")}
	ColorHot      = compat.AdaptiveColor{Light: lipgloss.Color("#A6006E"), Dark: lipgloss.Color("#FF72D0")}

	ColorPrimary = ColorIdentity
	ColorSuccess = ColorSignal
	ColorWarning = compat.AdaptiveColor{Light: lipgloss.Color("#7A3D00"), Dark: lipgloss.Color("#FFD07A")}
	ColorError   = compat.AdaptiveColor{Light: lipgloss.Color("#B4234F"), Dark: lipgloss.Color("#FF8AAF")}
	ColorInfo    = ColorBlue
	ColorMuted   = compat.AdaptiveColor{Light: lipgloss.Color("#4A5278"), Dark: lipgloss.Color("#AEB4D4")}
	ColorText    = compat.AdaptiveColor{Light: lipgloss.Color("#14172B"), Dark: lipgloss.Color("#F4F3FF")}
)

// Base styles
var (
	// Title styles
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPrimary).
			MarginBottom(1)

	SubtitleStyle = lipgloss.NewStyle().
			Foreground(ColorMuted).
			Italic(true)

	// Box styles
	BoxStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(ColorPrimary).
			Padding(1, 2)

	// Status indicators
	SuccessStyle = lipgloss.NewStyle().
			Foreground(ColorSuccess).
			Bold(true)

	WarningStyle = lipgloss.NewStyle().
			Foreground(ColorWarning).
			Bold(true)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(ColorError).
			Bold(true)

	InfoStyle = lipgloss.NewStyle().
			Foreground(ColorInfo)

	MutedStyle = lipgloss.NewStyle().
			Foreground(ColorMuted)

	// CommandStyle for rendering CLI commands in help text
	CommandStyle = lipgloss.NewStyle().
			Foreground(ColorInfo).
			Bold(true)

	// Interactive elements
	SelectedStyle = lipgloss.NewStyle().
			Foreground(ColorPrimary).
			Bold(true)

	FocusedStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(ColorPrimary).
			Padding(0, 1)

	// Table styles
	TableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorPrimary).
				Padding(0, 1)

	TableCellStyle = lipgloss.NewStyle().
			Padding(0, 1)
)

// Status icons
const (
	IconSuccess = "✓"
	IconError   = "✗"
	IconWarning = "⚠"
	IconInfo    = "ℹ"
	IconRunning = "●"
	IconStopped = "○"
	IconSpinner = "◐"
	IconArrow   = "→"
	IconCheck   = "✓"
	IconCross   = "✗"
	IconLock    = "🔒"
	IconUnlock  = "🔓"
	IconStar    = "★"
	IconDot     = "•"
	IconDash    = "─"
	IconBox     = "▪"
	IconFolder  = "📁"
	IconGear    = "⚙"
	IconNetwork = "🌐"
	IconDocker  = "🐳"
	IconKey     = "🔑"
	IconRocket  = "🚀"
	IconPackage = "📦"
)

// Logo is the ASCII art logo for SDBX
const Logo = `
███████╗██████╗ ██████╗ ██╗  ██╗
██╔════╝██╔══██╗██╔══██╗╚██╗██╔╝
███████╗██║  ██║██████╔╝ ╚███╔╝
╚════██║██║  ██║██╔══██╗ ██╔██╗
███████║██████╔╝██████╔╝██╔╝ ██╗
╚══════╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝`

const SceneTagline = "SDBX(1) // SEEDBOX IN A BOX // UNDER YOUR ROOT"

// LogoStyled returns the logo with styling applied
func LogoStyled() string {
	logo := Render(lipgloss.NewStyle().
		Foreground(ColorPrimary).
		Bold(true),
		Logo)
	tagline := Render(lipgloss.NewStyle().
		Foreground(ColorSignal),
		SceneTagline)
	return lipgloss.JoinVertical(lipgloss.Left, logo, tagline)
}

// RenderStatus returns a styled status indicator
func RenderStatus(healthy bool) string {
	if healthy {
		return Render(SuccessStyle, IconSuccess+" Healthy")
	}
	return Render(ErrorStyle, IconError+" Unhealthy")
}

// RenderServiceStatus returns a styled service status line
func RenderServiceStatus(name string, running bool, healthy bool) string {
	var icon string
	var style lipgloss.Style

	if !running {
		icon = IconStopped
		style = MutedStyle
	} else if healthy {
		icon = IconRunning
		style = SuccessStyle
	} else {
		icon = IconRunning
		style = WarningStyle
	}

	return Render(style, icon) + " " + name
}

// ProgressBar renders a simple progress bar
func ProgressBar(percent float64, width int) string {
	filled := int(float64(width) * percent)
	empty := width - filled

	bar := ""
	for i := 0; i < filled; i++ {
		bar += "█"
	}
	for i := 0; i < empty; i++ {
		bar += "░"
	}

	return Render(lipgloss.NewStyle().Foreground(ColorPrimary), bar)
}

// RenderSuccessBox returns a polished success message box
func RenderSuccessBox(title, message string) string {
	return Render(lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(ColorSuccess).
		Padding(1, 2).
		Margin(1, 0),

		lipgloss.JoinVertical(
			lipgloss.Left, Render(SuccessStyle.Copy().Foreground(ColorSuccess).Bold(true), IconSuccess+" "+title), "", Render(lipgloss.NewStyle().Foreground(ColorText), message),
		),
	)
}

// RenderInfoBox returns a styled information box
func RenderInfoBox(title, message string) string {
	return Render(lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(ColorInfo).
		Padding(1, 2).
		Margin(1, 0),

		lipgloss.JoinVertical(
			lipgloss.Left, Render(InfoStyle.Copy().Bold(true), IconInfo+" "+title), "", Render(lipgloss.NewStyle().Foreground(ColorText), message),
		),
	)
}

// RenderErrorBox returns a styled error box
func RenderErrorBox(title, message string) string {
	return Render(lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(ColorError).
		Padding(1, 2).
		Margin(1, 0),

		lipgloss.JoinVertical(
			lipgloss.Left, Render(ErrorStyle.Copy().Bold(true), IconError+" "+title), "", Render(lipgloss.NewStyle().Foreground(ColorText), message),
		),
	)
}

// RenderWarningBox returns a styled warning box
func RenderWarningBox(title, message string) string {
	return Render(lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(ColorWarning).
		Padding(1, 2).
		Margin(1, 0),

		lipgloss.JoinVertical(
			lipgloss.Left, Render(WarningStyle.Copy().Bold(true), IconWarning+" "+title), "", Render(lipgloss.NewStyle().Foreground(ColorText), message),
		),
	)
}

// RenderSection renders a styled section header
func RenderSection(title string) string {
	return Render(lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorPrimary).
		MarginTop(1),
		title)
}

// RenderKeyValue renders a styled key-value pair
func RenderKeyValue(key, value string) string {
	keyStyle := lipgloss.NewStyle().Foreground(ColorMuted).Width(14)
	return Render(keyStyle, EscapeText(key)+":") + " " + EscapeText(value)
}

// RenderBullet renders a bulleted list item
func RenderBullet(text string) string {
	return Render(MutedStyle, "  "+IconDot+" ") + text
}

// RenderCommand renders a styled command hint
func RenderCommand(cmd string) string {
	return Render(CommandStyle, cmd)
}

// RenderDivider renders a horizontal divider line
func RenderDivider(width int) string {
	line := ""
	for i := 0; i < width; i++ {
		line += IconDash
	}
	return Render(MutedStyle, line)
}

// RenderHeader renders a styled header with optional subtitle
func RenderHeader(title string, subtitle string) string {
	result := Render(TitleStyle, title)
	if subtitle != "" {
		result += "\n" + Render(SubtitleStyle, subtitle)
	}
	return result
}

// RenderStats renders statistics in a formatted way
func RenderStats(stats map[string]string) string {
	var parts []string
	for key, value := range stats {
		parts = append(parts, Render(MutedStyle, key+": ")+Render(SuccessStyle, value))
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

// Spinner characters for animation
var SpinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// CategoryColors maps service categories to colors
var CategoryColors = map[string]compat.AdaptiveColor{
	"media":      ColorHot,
	"downloads":  ColorSignal,
	"management": ColorIdentity,
	"utility":    ColorWarning,
	"networking": ColorBlue,
	"auth":       ColorError,
}

// RenderCategory renders a styled category tag
func RenderCategory(category string) string {
	color, ok := CategoryColors[category]
	if !ok {
		color = ColorMuted
	}
	return Render(lipgloss.NewStyle().
		Foreground(color).
		Bold(true),
		EscapeText(category))
}

// EscapeText makes untrusted text inert before terminal rendering. Structured
// output must keep using its native encoder instead of this presentation form.
func EscapeText(value string) string {
	var escaped strings.Builder
	escaped.Grow(len(value))
	for _, character := range value {
		switch character {
		case '\n':
			escaped.WriteString(`\n`)
		case '\r':
			escaped.WriteString(`\r`)
		case '\t':
			escaped.WriteString(`\t`)
		default:
			if unicode.IsControl(character) || unicode.Is(unicode.Bidi_Control, character) {
				switch {
				case character <= 0xff:
					_, _ = fmt.Fprintf(&escaped, `\x%02X`, character)
				case character <= 0xffff:
					_, _ = fmt.Fprintf(&escaped, `\u%04X`, character)
				default:
					_, _ = fmt.Fprintf(&escaped, `\U%08X`, character)
				}
				continue
			}
			escaped.WriteRune(character)
		}
	}
	return escaped.String()
}
