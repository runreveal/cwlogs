package lib

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/segmentio/bellows"
	"github.com/segmentio/ecs-logs-go"
)

const (
	// ShortTimeFormat is a short format for printing timestamps
	ShortTimeFormat = "01-02 15:04:05"
)

// TaskUUIDPattern is used to match task UUIDs
var TaskUUIDPattern = regexp.MustCompile(`^[[:alnum:]]{8}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{12}$`)

// Event represents a log event
type Event struct {
	SlogEvent
	Stream       string
	Group        string
	ID           string
	IngestTime   time.Time
	CreationTime time.Time
}

type SlogEvent struct {
	Level   ecslogs.Level     `json:"level"`
	Time    time.Time         `json:"time"`
	Source  SourceInfo        `json:"source"`
	Message string            `json:"msg"`
	Data    map[string]string `json:"-"`
}

type SourceInfo struct {
	Function string `json:"function"`
	File     string `json:"file"`
	Line     int    `json:"line"`
}

func (s *SlogEvent) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if levelData, ok := raw["level"]; ok {
		if err := json.Unmarshal(levelData, &s.Level); err != nil {
			return err
		}
	}

	if timeData, ok := raw["time"]; ok {
		if err := json.Unmarshal(timeData, &s.Time); err != nil {
			return err
		}
	}

	if sourceData, ok := raw["source"]; ok {
		if err := json.Unmarshal(sourceData, &s.Source); err != nil {
			return err
		}
	}

	if msgData, ok := raw["msg"]; ok {
		if err := json.Unmarshal(msgData, &s.Message); err != nil {
			return err
		}
	}

	s.Data = make(map[string]string)
	staticFields := map[string]bool{
		"level":  true,
		"time":   true,
		"source": true,
		"msg":    true,
	}

	for key, value := range raw {
		if !staticFields[key] {
			var str string
			if err := json.Unmarshal(value, &str); err != nil {
				var num json.Number
				if err := json.Unmarshal(value, &num); err != nil {
					s.Data[key] = string(value)
				} else {
					s.Data[key] = string(num)
				}
			} else {
				s.Data[key] = str
			}
		}
	}

	return nil
}

// NewEvent takes a cloudwatch log event and returns an Event
func NewEvent(cwEvent cloudwatchlogs.FilteredLogEvent, group string) Event {
	var ecsLogsEvent SlogEvent
	if err := json.Unmarshal([]byte(*cwEvent.Message), &ecsLogsEvent); err != nil {
		ecsLogsEvent = SlogEvent{
			Level:   ecslogs.INFO,
			Message: *cwEvent.Message,
		}
	}

	// If time was not found use AWS Timestamp
	if ecsLogsEvent.Time.IsZero() {
		ecsLogsEvent.Time = ParseAWSTimestamp(cwEvent.Timestamp)
	}

	return Event{
		SlogEvent:        ecsLogsEvent,
		Stream:       *cwEvent.LogStreamName,
		Group:        group,
		ID:           *cwEvent.EventId,
		IngestTime:   ParseAWSTimestamp(cwEvent.IngestionTime),
		CreationTime: ParseAWSTimestamp(cwEvent.Timestamp),
	}

}

// ParseAWSTimestamp takes the time stamp format given by AWS and returns an equivalent time.Time value
func ParseAWSTimestamp(i *int64) time.Time {
	if i == nil {
		return time.Unix(0, 0)
	}
	return time.Unix(*i/1e3, (*i%1e3)*1e6)
}

// TaskShort attempts to shorten a stream name if it is a task UUID, leaving the stream
// name intact if it is not a UUID
func (e Event) TaskShort() string {
	if TaskUUIDPattern.MatchString(e.Stream) {
		uuidParts := strings.Split(e.Stream, "-")
		return uuidParts[0]
	}
	return e.Stream
}

// TimeShort gives the timestamp of an event in a readable format
func (e Event) TimeShort() string {
	return e.Time.Local().Format(ShortTimeFormat)
}

func (e Event) DataFlat() map[string]interface{} {
	return bellows.Flatten(e.Data)
}

func (e Event) PrettyPrint() string {
	pretty, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return fmt.Sprintf("%+v", e)
	}
	return string(pretty)
}

// ByCreationTime is used to sort events by their creation time
type ByCreationTime []Event

func (b ByCreationTime) Len() int           { return len(b) }
func (b ByCreationTime) Swap(i, j int)      { b[i], b[j] = b[j], b[i] }
func (b ByCreationTime) Less(i, j int) bool { return b[i].CreationTime.Before(b[j].CreationTime) }
