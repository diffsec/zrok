// Package config imports a cloned repo's .quokka/ directory into the DB. It
// is called by the InstallRepo job after a successful clone, and by
// RunPR/RunManual jobs that need to reconcile repo-side config drift.
//
// The export half (DB → YAML for the "Commit to repo" PR) lives in
// export.go (a stub for PR-4 — Brief C ships it).
package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/diffsec/quokka/internal/agent"
	"github.com/diffsec/quokka/internal/exception"
	"github.com/diffsec/quokka/internal/project"
	"github.com/diffsec/quokka/internal/store"
	"gopkg.in/yaml.v3"
)

// ImportResult is the set of DB rows the importer wrote on a single pass.
type ImportResult struct {
	AgentConfigs []string
	Exceptions   []string
	Memories     []string
	ProjectFound bool
}

// Import reads <rootPath>/.quokka/{project.yaml,agents/*.yaml,exceptions.yaml,memories/*.yaml}
// and upserts the corresponding DB rows scoped to orgID + repoID.
//
// commitSHA is recorded in agent_config_revisions.import_sha. A zero
// ImportResult + nil error means no .quokka/ directory was found.
func Import(ctx context.Context, stores *store.Stores, orgID, repoID, rootPath, commitSHA string) (*ImportResult, error) {
	if stores == nil {
		return nil, errors.New("config: nil stores")
	}
	res := &ImportResult{}
	qdir := filepath.Join(rootPath, ".quokka")
	st, err := os.Stat(qdir)
	if err != nil || !st.IsDir() {
		return res, nil
	}
	// project.yaml: stash classification + tech stack + security scope JSON
	// in the repositories row.
	p, perr := importProject(filepath.Join(qdir, "project.yaml"))
	if perr == nil && p != nil {
		res.ProjectFound = true
		if err := updateRepoClassification(ctx, stores, repoID, p); err != nil {
			return res, fmt.Errorf("project.yaml: %w", err)
		}
	} else if perr != nil && !errors.Is(perr, os.ErrNotExist) {
		return res, fmt.Errorf("project.yaml: %w", perr)
	}
	// agents/*.yaml
	agentsDir := filepath.Join(qdir, "agents")
	if entries, err := os.ReadDir(agentsDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
				continue
			}
			id, err := importAgent(ctx, stores, orgID, filepath.Join(agentsDir, e.Name()), commitSHA)
			if err != nil {
				return res, fmt.Errorf("agent %s: %w", e.Name(), err)
			}
			if id != "" {
				res.AgentConfigs = append(res.AgentConfigs, id)
			}
		}
	}
	// exceptions.yaml
	if ids, err := importExceptions(ctx, stores, repoID, filepath.Join(qdir, "exceptions.yaml")); err == nil {
		res.Exceptions = ids
	} else if !errors.Is(err, os.ErrNotExist) {
		return res, fmt.Errorf("exceptions.yaml: %w", err)
	}
	// memories/**/*.yaml
	memDir := filepath.Join(qdir, "memories")
	if entries, err := os.ReadDir(memDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
				continue
			}
			name, err := importMemory(ctx, stores, repoID, filepath.Join(memDir, e.Name()))
			if err != nil {
				return res, fmt.Errorf("memory %s: %w", e.Name(), err)
			}
			if name != "" {
				res.Memories = append(res.Memories, name)
			}
		}
	}
	return res, nil
}

// importProject reads .quokka/project.yaml and returns the parsed config.
func importProject(path string) (*project.ProjectConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p project.ProjectConfig
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// updateRepoClassification stashes the classification JSON on the
// repositories row. PR-5 reads it back to render badges + filter applicable
// agents.
func updateRepoClassification(ctx context.Context, stores *store.Stores, repoID string, p *project.ProjectConfig) error {
	repo, err := stores.Repos.Get(ctx, repoID)
	if err != nil {
		return err
	}
	combined := map[string]any{
		"classification": p.Classification,
		"tech_stack":     p.TechStack,
		"security_scope": p.SecurityScope,
		"index_config":   p.Index,
	}
	b, _ := json.Marshal(combined)
	repo.ClassificationJSON = string(b)
	return stores.Repos.Update(ctx, repo)
}

// importAgent upserts the agent_configs row + a new revision pointing at
// the imported commit SHA. Returns the agent_config_id.
func importAgent(ctx context.Context, stores *store.Stores, orgID, path, commitSHA string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	cfg, err := agent.LoadStrict(data)
	if err != nil {
		// Fall back to non-strict for forward-compat fields.
		var lax agent.AgentConfig
		if err2 := yaml.Unmarshal(data, &lax); err2 != nil {
			return "", err
		}
		cfg = &lax
	}
	if cfg.Name == "" {
		return "", errors.New("agent yaml: name is empty")
	}
	row := &store.AgentConfigRow{
		OrgID:       orgID,
		Name:        cfg.Name,
		Description: cfg.Description,
		Phase:       string(cfg.Phase),
		Source:      "repo-import",
	}
	if err := stores.AgentConfigs.Create(ctx, row); err != nil {
		return "", err
	}
	// Reload to pick up the assigned ID when the upsert went through the
	// ON CONFLICT path.
	got, err := stores.AgentConfigs.GetByName(ctx, orgID, cfg.Name)
	if err != nil {
		return "", err
	}
	modelJSON := ""
	if cfg.ModelConfig != nil {
		b, _ := json.Marshal(cfg.ModelConfig)
		modelJSON = string(b)
	}
	rev := &store.AgentConfigRevision{
		AgentConfigID:   got.ID,
		YAML:            string(data),
		ModelConfigJSON: modelJSON,
		ImportSHA:       commitSHA,
	}
	if err := stores.AgentConfigs.NewRevision(ctx, rev); err != nil {
		return got.ID, err
	}
	if err := stores.AgentConfigs.SetActiveRevision(ctx, got.ID, rev.ID); err != nil {
		return got.ID, err
	}
	return got.ID, nil
}

// importExceptions reads exceptions.yaml as a top-level list and writes one
// store.ExceptionRow per entry.
func importExceptions(ctx context.Context, stores *store.Stores, repoID, path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var list []exception.Exception
	if err := yaml.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range list {
		if err := e.Validate(); err != nil {
			return ids, fmt.Errorf("invalid exception %q: %w", e.ID, err)
		}
		row := &store.ExceptionRow{
			RepoID:      repoID,
			Fingerprint: e.Fingerprint,
			PathGlob:    e.PathGlob,
			CWE:         e.CWE,
			AgentName:   e.AgentName,
			Reason:      e.Reason,
			Expires:     e.Expires,
			ApprovedBy:  e.ApprovedBy,
			ApprovedFor: e.ApprovedFor,
		}
		if row.Expires.IsZero() {
			row.Expires = time.Now().AddDate(0, 3, 0)
		}
		if err := stores.Exceptions.Create(ctx, row); err != nil {
			return ids, err
		}
		ids = append(ids, row.ID)
	}
	return ids, nil
}

// memoryFile is the on-disk shape under .quokka/memories/*.yaml.
type memoryFile struct {
	Name        string   `yaml:"name"`
	Type        string   `yaml:"type"`
	Description string   `yaml:"description"`
	Content     string   `yaml:"content"`
	Tags        []string `yaml:"tags"`
	CreatedBy   string   `yaml:"created_by"`
}

func importMemory(ctx context.Context, stores *store.Stores, repoID, path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var m memoryFile
	if err := yaml.Unmarshal(data, &m); err != nil {
		return "", err
	}
	if m.Name == "" {
		m.Name = strings.TrimSuffix(filepath.Base(path), ".yaml")
	}
	if m.Type == "" {
		m.Type = "context"
	}
	tagsJSON := ""
	if len(m.Tags) > 0 {
		b, _ := json.Marshal(m.Tags)
		tagsJSON = string(b)
	}
	row := &store.MemoryRow{
		RepoID:      repoID,
		Name:        m.Name,
		Type:        m.Type,
		Description: m.Description,
		Content:     m.Content,
		TagsJSON:    tagsJSON,
		CreatedBy:   m.CreatedBy,
	}
	if err := stores.Memories.Upsert(ctx, row); err != nil {
		return "", err
	}
	return m.Name, nil
}
