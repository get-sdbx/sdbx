// Package tui provides TUI components and styles for sdbx.
package tui

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/charmbracelet/lipgloss"
)

// Color palette adapts to light and dark terminal backgrounds. The semantic
// roles mirror the website and Web UI: violet carries identity, cyan signals
// healthy or active state, blue carries information, and magenta is reserved
// for rare high-energy labels. Every text color meets a 4.5:1 contrast ratio
// against its corresponding background.
var (
	ColorIdentity = lipgloss.AdaptiveColor{Light: "#5B21B6", Dark: "#B78CFF"}
	ColorSignal   = lipgloss.AdaptiveColor{Light: "#006377", Dark: "#4DEAFF"}
	ColorBlue     = lipgloss.AdaptiveColor{Light: "#2446B8", Dark: "#9BAEFF"}
	ColorHot      = lipgloss.AdaptiveColor{Light: "#A6006E", Dark: "#FF72D0"}

	ColorPrimary = ColorIdentity
	ColorSuccess = ColorSignal
	ColorWarning = lipgloss.AdaptiveColor{Light: "#7A3D00", Dark: "#FFD07A"}
	ColorError   = lipgloss.AdaptiveColor{Light: "#B4234F", Dark: "#FF8AAF"}
	ColorInfo    = ColorBlue
	ColorMuted   = lipgloss.AdaptiveColor{Light: "#4A5278", Dark: "#AEB4D4"}
	ColorText    = lipgloss.AdaptiveColor{Light: "#14172B", Dark: "#F4F3FF"}
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
	logo := lipgloss.NewStyle().
		Foreground(ColorPrimary).
		Bold(true).
		Render(Logo)
	tagline := lipgloss.NewStyle().
		Foreground(ColorSignal).
		Render(SceneTagline)
	return lipgloss.JoinVertical(lipgloss.Left, logo, tagline)
}

// RenderStatus returns a styled status indicator
func RenderStatus(healthy bool) string {
	if healthy {
		return SuccessStyle.Render(IconSuccess + " Healthy")
	}
	return ErrorStyle.Render(IconError + " Unhealthy")
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

	return style.Render(icon) + " " + name
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

	return lipgloss.NewStyle().Foreground(ColorPrimary).Render(bar)
}

// RenderSuccessBox returns a polished success message box
func RenderSuccessBox(title, message string) string {
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(ColorSuccess).
		Padding(1, 2).
		Margin(1, 0).
		Render(
			lipgloss.JoinVertical(
				lipgloss.Left,
				SuccessStyle.Copy().Foreground(ColorSuccess).Bold(true).Render(IconSuccess+" "+title),
				"",
				lipgloss.NewStyle().Foreground(ColorText).Render(message),
			),
		)
}

// RenderInfoBox returns a styled information box
func RenderInfoBox(title, message string) string {
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(ColorInfo).
		Padding(1, 2).
		Margin(1, 0).
		Render(
			lipgloss.JoinVertical(
				lipgloss.Left,
				InfoStyle.Copy().Bold(true).Render(IconInfo+" "+title),
				"",
				lipgloss.NewStyle().Foreground(ColorText).Render(message),
			),
		)
}

// RenderErrorBox returns a styled error box
func RenderErrorBox(title, message string) string {
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(ColorError).
		Padding(1, 2).
		Margin(1, 0).
		Render(
			lipgloss.JoinVertical(
				lipgloss.Left,
				ErrorStyle.Copy().Bold(true).Render(IconError+" "+title),
				"",
				lipgloss.NewStyle().Foreground(ColorText).Render(message),
			),
		)
}

// RenderWarningBox returns a styled warning box
func RenderWarningBox(title, message string) string {
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(ColorWarning).
		Padding(1, 2).
		Margin(1, 0).
		Render(
			lipgloss.JoinVertical(
				lipgloss.Left,
				WarningStyle.Copy().Bold(true).Render(IconWarning+" "+title),
				"",
				lipgloss.NewStyle().Foreground(ColorText).Render(message),
			),
		)
}

// RenderSection renders a styled section header
func RenderSection(title string) string {
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorPrimary).
		MarginTop(1).
		Render(title)
}

// RenderKeyValue renders a styled key-value pair
func RenderKeyValue(key, value string) string {
	keyStyle := lipgloss.NewStyle().Foreground(ColorMuted).Width(14)
	return keyStyle.Render(EscapeText(key)+":") + " " + EscapeText(value)
}

// RenderBullet renders a bulleted list item
func RenderBullet(text string) string {
	return MutedStyle.Render("  "+IconDot+" ") + text
}

// RenderCommand renders a styled command hint
func RenderCommand(cmd string) string {
	return CommandStyle.Render(cmd)
}

// RenderDivider renders a horizontal divider line
func RenderDivider(width int) string {
	line := ""
	for i := 0; i < width; i++ {
		line += IconDash
	}
	return MutedStyle.Render(line)
}

// RenderHeader renders a styled header with optional subtitle
func RenderHeader(title string, subtitle string) string {
	result := TitleStyle.Render(title)
	if subtitle != "" {
		result += "\n" + SubtitleStyle.Render(subtitle)
	}
	return result
}

// RenderStats renders statistics in a formatted way
func RenderStats(stats map[string]string) string {
	var parts []string
	for key, value := range stats {
		parts = append(parts, MutedStyle.Render(key+": ")+SuccessStyle.Render(value))
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

// Spinner characters for animation
var SpinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// CategoryColors maps service categories to colors
var CategoryColors = map[string]lipgloss.AdaptiveColor{
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
	return lipgloss.NewStyle().
		Foreground(color).
		Bold(true).
		Render(EscapeText(category))
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
