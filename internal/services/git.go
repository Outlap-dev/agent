package services

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/http"

	wscontracts "outlap-agent-go/pkg/contracts/websocket"
	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

// GitServiceImpl implements the GitService interface
type GitServiceImpl struct {
	logger       *logger.Logger
	wsManager    wscontracts.Caller
	baseCloneDir string
}

// NewGitService creates a new Git service
func NewGitService(logger *logger.Logger) *GitServiceImpl {
	baseCloneDir := "/opt/outlap/apps"

	// Check if we're in debug mode
	if os.Getenv("DEBUG") == "true" {
		if debugDir := os.Getenv("DEBUG_CLONE_DIR"); debugDir != "" {
			baseCloneDir = debugDir
		}
	}

	return &GitServiceImpl{
		logger:       logger.With("service", "git"),
		baseCloneDir: baseCloneDir,
	}
}

// SetWebSocketManager sets the WebSocket manager for making server calls
func (g *GitServiceImpl) SetWebSocketManager(wsManager wscontracts.Caller) {
	g.wsManager = wsManager
	g.logger.Debug("WebSocket manager set for Git service")
}

// GetGitHubRepoInfo gets GitHub repository information for a service from the server
func (g *GitServiceImpl) GetGitHubRepoInfo(ctx context.Context, serviceUID string) (*types.GitHubRepoInfo, error) {
	g.logger.Debug("Getting GitHub repo info", "service_uid", serviceUID)

	if g.wsManager == nil {
		return nil, fmt.Errorf("websocket manager not available")
	}

	// Make the call to get GitHub repo info
	result, err := g.wsManager.Call("get_github_repo", map[string]interface{}{
		"service_uid": serviceUID,
	})
	if err != nil {
		g.logger.Error("Failed to get GitHub repo info", "service_uid", serviceUID, "error", err)
		return nil, fmt.Errorf("failed to get GitHub repo info: %w", err)
	}

	// Parse the result
	repoInfo := &types.GitHubRepoInfo{}
	if errorMsg, exists := result["error"]; exists {
		repoInfo.Error = fmt.Sprintf("%v", errorMsg)
		return repoInfo, nil
	}

	if repoURL, exists := result["repo_url"]; exists {
		repoInfo.RepoURL = fmt.Sprintf("%v", repoURL)
	}

	if accessToken, exists := result["access_token"]; exists {
		repoInfo.AccessToken = fmt.Sprintf("%v", accessToken)
	}

	if repoInfo.RepoURL == "" || repoInfo.AccessToken == "" {
		return nil, fmt.Errorf("missing repo_url or access_token in response")
	}

	g.logger.Debug("Retrieved GitHub repo info", "service_uid", serviceUID)
	return repoInfo, nil
}

// constructCloneURL constructs the clone URL with embedded access token
func (g *GitServiceImpl) constructCloneURL(repoURL, accessToken string) (string, error) {
	// Ensure the repo_url is a full HTTPS URL
	if !strings.HasPrefix(repoURL, "http") {
		repoURL = fmt.Sprintf("https://github.com/%s", strings.TrimSpace(repoURL))
	}

	parsedURL, err := url.Parse(repoURL)
	if err != nil {
		return "", fmt.Errorf("invalid repository URL: %w", err)
	}

	// Ensure scheme is https for token auth
	if parsedURL.Scheme != "https" {
		return "", fmt.Errorf("repository URL must use https for token authentication: %s", repoURL)
	}

	// Inject token: https://oauth2:<token>@github.com/user/repo.git
	cloneURL := fmt.Sprintf("https://oauth2:%s@%s%s", accessToken, parsedURL.Host, parsedURL.Path)
	g.logger.Debug("Constructed clone URL (token omitted from log)", "url", fmt.Sprintf("https://oauth2:<token>@%s%s", parsedURL.Host, parsedURL.Path))
	return cloneURL, nil
}

// CloneGitHubRepo clones a GitHub repository using service UID to get repo info
func (g *GitServiceImpl) CloneGitHubRepo(ctx context.Context, serviceUID string) (*types.CloneResult, error) {
	g.logger.Info("Cloning GitHub repository", "service_uid", serviceUID)

	// Construct the clone path using the service UID
	clonePath := filepath.Join(g.baseCloneDir, serviceUID)

	// Check if directory already exists
	if _, err := os.Stat(clonePath); err == nil {
		g.logger.Info("Repository already exists", "clone_path", clonePath)
		return &types.CloneResult{
			Success:   true,
			ClonePath: clonePath,
		}, nil
	}

	// Get GitHub repo info from server
	repoInfo, err := g.GetGitHubRepoInfo(ctx, serviceUID)
	if err != nil {
		return &types.CloneResult{
			Success: false,
			Error:   fmt.Sprintf("failed to get repo info: %v", err),
		}, nil
	}

	if repoInfo.Error != "" {
		return &types.CloneResult{
			Success: false,
			Error:   repoInfo.Error,
		}, nil
	}

	// Construct the clone URL with token
	cloneURL, err := g.constructCloneURL(repoInfo.RepoURL, repoInfo.AccessToken)
	if err != nil {
		return &types.CloneResult{
			Success: false,
			Error:   fmt.Sprintf("failed to construct clone URL: %v", err),
		}, nil
	}

	// Ensure the target directory exists
	if err := os.MkdirAll(clonePath, 0755); err != nil {
		return &types.CloneResult{
			Success: false,
			Error:   fmt.Sprintf("failed to create clone directory: %v", err),
		}, nil
	}

	// Clone the repository
	cloneOptions := &git.CloneOptions{
		URL: cloneURL,
		Auth: &http.BasicAuth{
			Username: "oauth2",
			Password: repoInfo.AccessToken,
		},
	}

	_, err = git.PlainCloneContext(ctx, clonePath, false, cloneOptions)
	if err != nil {
		return &types.CloneResult{
			Success: false,
			Error:   fmt.Sprintf("git clone failed: %v", err),
		}, nil
	}

	g.logger.Info("Repository cloned successfully", "clone_path", clonePath)
	return &types.CloneResult{
		Success:   true,
		ClonePath: clonePath,
	}, nil
}

// PullGitHubRepo pulls the latest changes from a GitHub repository
func (g *GitServiceImpl) PullGitHubRepo(ctx context.Context, serviceUID string) (*types.CloneResult, error) {
	g.logger.Info("Pulling GitHub repository", "service_uid", serviceUID)

	clonePath := filepath.Join(g.baseCloneDir, serviceUID)
	if _, err := os.Stat(clonePath); os.IsNotExist(err) {
		return &types.CloneResult{
			Success: false,
			Error:   fmt.Sprintf("repository %s not found in %s", serviceUID, clonePath),
		}, nil
	}

	// Get fresh repo info with new access token
	repoInfo, err := g.GetGitHubRepoInfo(ctx, serviceUID)
	if err != nil {
		return &types.CloneResult{
			Success: false,
			Error:   fmt.Sprintf("failed to get repo info: %v", err),
		}, nil
	}

	if repoInfo.Error != "" {
		return &types.CloneResult{
			Success: false,
			Error:   repoInfo.Error,
		}, nil
	}

	// For now, use the existing PullLatest method
	// TODO: Implement proper GitHub token-based pulling
	err = g.PullLatest(ctx, clonePath)
	if err != nil {
		return &types.CloneResult{
			Success: false,
			Error:   fmt.Sprintf("failed to pull: %v", err),
		}, nil
	}

	g.logger.Info("Repository pulled successfully", "clone_path", clonePath)
	return &types.CloneResult{
		Success:   true,
		ClonePath: clonePath,
	}, nil
}

// CloneRepository clones a Git repository
func (g *GitServiceImpl) CloneRepository(ctx context.Context, gitURL, branch, destination string) error {
	g.logger.Info("Cloning repository", "url", gitURL, "branch", branch, "destination", destination)

	// Create destination directory if it doesn't exist
	if err := os.MkdirAll(destination, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	cloneOptions := &git.CloneOptions{
		URL: gitURL,
	}

	// If branch is specified, clone specific branch
	if branch != "" {
		cloneOptions.ReferenceName = plumbing.ReferenceName(fmt.Sprintf("refs/heads/%s", branch))
		cloneOptions.SingleBranch = true
	}

	_, err := git.PlainCloneContext(ctx, destination, false, cloneOptions)
	if err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}

	g.logger.Info("Repository cloned successfully", "destination", destination)
	return nil
}

// GetCommitSHA returns the current commit SHA
func (g *GitServiceImpl) GetCommitSHA(ctx context.Context, repoPath string) (string, error) {
	g.logger.Debug("Getting commit SHA", "repo_path", repoPath)

	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return "", fmt.Errorf("failed to open repository: %w", err)
	}

	ref, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf("failed to get HEAD reference: %w", err)
	}

	sha := ref.Hash().String()
	g.logger.Debug("Retrieved commit SHA", "sha", sha)
	return sha, nil
}

// GetCommitMessage returns the commit message for a specific SHA in the repository
func (g *GitServiceImpl) GetCommitMessage(ctx context.Context, repoPath, sha string) (string, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return "", fmt.Errorf("failed to open repository: %w", err)
	}

	hash := plumbing.NewHash(sha)
	commit, err := repo.CommitObject(hash)
	if err != nil {
		return "", fmt.Errorf("failed to load commit %s: %w", sha, err)
	}

	return commit.Message, nil
}

// PullLatest pulls the latest changes
func (g *GitServiceImpl) PullLatest(ctx context.Context, repoPath string) error {
	g.logger.Info("Pulling latest changes", "repo_path", repoPath)

	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return fmt.Errorf("failed to open repository: %w", err)
	}

	workTree, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	err = workTree.PullContext(ctx, &git.PullOptions{
		RemoteName: "origin",
	})
	if err != nil && err != git.NoErrAlreadyUpToDate {
		return fmt.Errorf("failed to pull latest changes: %w", err)
	}

	if err == git.NoErrAlreadyUpToDate {
		g.logger.Info("Repository is already up to date")
	} else {
		g.logger.Info("Successfully pulled latest changes")
	}

	return nil
}

// GetBranches returns all branches
func (g *GitServiceImpl) GetBranches(ctx context.Context, repoPath string) ([]string, error) {
	g.logger.Debug("Getting branches", "repo_path", repoPath)

	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	refs, err := repo.References()
	if err != nil {
		return nil, fmt.Errorf("failed to get references: %w", err)
	}

	var branches []string
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		if ref.Name().IsBranch() {
			branchName := ref.Name().Short()
			branches = append(branches, branchName)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to iterate references: %w", err)
	}

	g.logger.Debug("Retrieved branches", "count", len(branches), "branches", branches)
	return branches, nil
}

// CheckoutBranch checks out a specific branch
func (g *GitServiceImpl) CheckoutBranch(ctx context.Context, repoPath, branch string) error {
	g.logger.Info("Checking out branch", "repo_path", repoPath, "branch", branch)

	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return fmt.Errorf("failed to open repository: %w", err)
	}

	workTree, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	// Check if branch exists locally
	branchRef := plumbing.ReferenceName(fmt.Sprintf("refs/heads/%s", branch))
	_, err = repo.Reference(branchRef, true)

	checkoutOptions := &git.CheckoutOptions{
		Branch: branchRef,
		Force:  true,
	}

	// If branch doesn't exist locally, try to create it from remote
	if err != nil {
		remoteRef := plumbing.ReferenceName(fmt.Sprintf("refs/remotes/origin/%s", branch))
		_, err = repo.Reference(remoteRef, true)
		if err != nil {
			return fmt.Errorf("branch '%s' not found locally or remotely: %w", branch, err)
		}

		checkoutOptions.Create = true
	}

	err = workTree.Checkout(checkoutOptions)
	if err != nil {
		return fmt.Errorf("failed to checkout branch '%s': %w", branch, err)
	}

	if resetErr := g.hardResetBranch(repo, branch); resetErr != nil {
		g.logger.Debug("Branch checkout completed without reset", "branch", branch, "error", resetErr)
	}

	g.logger.Info("Successfully checked out branch", "branch", branch)
	return nil
}

func (g *GitServiceImpl) hardResetBranch(repo *git.Repository, branch string) error {
	if repo == nil {
		return fmt.Errorf("repository is nil")
	}

	if branch == "" {
		head, err := repo.Head()
		if err != nil {
			return fmt.Errorf("failed to resolve current HEAD: %w", err)
		}
		if !head.Name().IsBranch() {
			return fmt.Errorf("HEAD is detached; cannot determine branch for reset")
		}
		branch = head.Name().Short()
	}

	workTree, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	remoteRef := plumbing.NewRemoteReferenceName("origin", branch)
	ref, err := repo.Reference(remoteRef, true)
	if err != nil {
		return fmt.Errorf("failed to locate remote branch '%s': %w", branch, err)
	}

	if err := workTree.Reset(&git.ResetOptions{
		Mode:   git.HardReset,
		Commit: ref.Hash(),
	}); err != nil {
		return fmt.Errorf("failed to reset branch '%s' to remote commit: %w", branch, err)
	}

	g.logger.Debug("Hard reset branch to remote head", "branch", branch, "commit", ref.Hash().String())
	return nil
}

// CloneGitHubRepoDirectly clones a GitHub repository using direct repo info (no server call)
func (g *GitServiceImpl) CloneGitHubRepoDirectly(ctx context.Context, repoURL, accessToken, clonePath, branch string) (*types.CloneResult, error) {
	g.logger.Info("Cloning GitHub repository directly", "repo_url", repoURL, "clone_path", clonePath)

	// Check if directory already exists
	if _, err := os.Stat(clonePath); err == nil {
		g.logger.Info("Repository already exists", "clone_path", clonePath)
		return &types.CloneResult{
			Success:   true,
			ClonePath: clonePath,
		}, nil
	}

	// Construct the clone URL with token
	cloneURL, err := g.constructCloneURL(repoURL, accessToken)
	if err != nil {
		return &types.CloneResult{
			Success: false,
			Error:   fmt.Sprintf("failed to construct clone URL: %v", err),
		}, nil
	}

	// Ensure the target directory exists
	if err := os.MkdirAll(clonePath, 0755); err != nil {
		return &types.CloneResult{
			Success: false,
			Error:   fmt.Sprintf("failed to create clone directory: %v", err),
		}, nil
	}

	// Clone the repository
	cloneOptions := &git.CloneOptions{
		URL: cloneURL,
		Auth: &http.BasicAuth{
			Username: "oauth2",
			Password: accessToken,
		},
	}

	// If a specific branch is requested, clone that branch only
	if branch != "" && branch != "main" && branch != "master" {
		cloneOptions.ReferenceName = plumbing.ReferenceName(fmt.Sprintf("refs/heads/%s", branch))
		cloneOptions.SingleBranch = true
	}

	_, err = git.PlainCloneContext(ctx, clonePath, false, cloneOptions)
	if err != nil {
		return &types.CloneResult{
			Success: false,
			Error:   fmt.Sprintf("git clone failed: %v", err),
		}, nil
	}

	// If branch is specified and we didn't use single branch clone, checkout the branch
	if branch != "" && (branch == "main" || branch == "master" || cloneOptions.ReferenceName == "") {
		if err := g.CheckoutBranch(ctx, clonePath, branch); err != nil {
			g.logger.Warn("Failed to checkout branch after clone", "branch", branch, "error", err)
			// Don't fail the clone if checkout fails, just log warning
		}
	}

	g.logger.Info("Repository cloned successfully", "clone_path", clonePath, "branch", branch)
	return &types.CloneResult{
		Success:   true,
		ClonePath: clonePath,
	}, nil
}

// PullGitHubRepoDirectly pulls the latest changes from a GitHub repository using direct token
func (g *GitServiceImpl) PullGitHubRepoDirectly(ctx context.Context, clonePath, accessToken, branch string) (*types.CloneResult, error) {
	g.logger.Info("Pulling GitHub repository directly", "clone_path", clonePath)

	if _, err := os.Stat(clonePath); os.IsNotExist(err) {
		return &types.CloneResult{
			Success: false,
			Error:   fmt.Sprintf("repository not found in %s", clonePath),
		}, nil
	}

	// Open the repository
	repo, err := git.PlainOpen(clonePath)
	if err != nil {
		return &types.CloneResult{
			Success: false,
			Error:   fmt.Sprintf("failed to open repository: %v", err),
		}, nil
	}

	auth := &http.BasicAuth{
		Username: "oauth2",
		Password: accessToken,
	}

	fetchOptions := &git.FetchOptions{
		RemoteName: "origin",
		Force:      true,
		Auth:       auth,
	}

	if branch != "" {
		refSpec := config.RefSpec(fmt.Sprintf("+refs/heads/%[1]s:refs/remotes/origin/%[1]s", branch))
		fetchOptions.RefSpecs = []config.RefSpec{refSpec}
	} else {
		fetchOptions.RefSpecs = []config.RefSpec{config.RefSpec("+refs/heads/*:refs/remotes/origin/*")}
	}

	if err := repo.FetchContext(ctx, fetchOptions); err != nil && err != git.NoErrAlreadyUpToDate {
		g.logger.Warn("Failed to fetch remote updates before pull", "error", err)
	}

	// If branch is specified, checkout the branch first
	if branch != "" {
		if err := g.CheckoutBranch(ctx, clonePath, branch); err != nil {
			g.logger.Warn("Failed to checkout branch before pull", "branch", branch, "error", err)
			// Continue with pull even if checkout fails
		}

		// Re-open repo to ensure we operate on the updated HEAD
		repo, err = git.PlainOpen(clonePath)
		if err != nil {
			return &types.CloneResult{
				Success: false,
				Error:   fmt.Sprintf("failed to reopen repository after checkout: %v", err),
			}, nil
		}
	}

	workTree, err := repo.Worktree()
	if err != nil {
		return &types.CloneResult{
			Success: false,
			Error:   fmt.Sprintf("failed to get worktree: %v", err),
		}, nil
	}

	// Pull with authentication
	pullOptions := &git.PullOptions{
		RemoteName: "origin",
		Auth:       auth,
	}

	// If specific branch is requested, pull that branch
	if branch != "" {
		pullOptions.ReferenceName = plumbing.ReferenceName(fmt.Sprintf("refs/heads/%s", branch))
	}

	pullErr := workTree.PullContext(ctx, pullOptions)
	targetBranch := branch
	if targetBranch == "" {
		if head, headErr := repo.Head(); headErr == nil && head.Name().IsBranch() {
			targetBranch = head.Name().Short()
		}
	}

	if pullErr != nil && pullErr != git.NoErrAlreadyUpToDate {
		g.logger.Warn("Pull failed, forcing hard reset to remote head", "branch", targetBranch, "error", pullErr)
		if resetErr := g.hardResetBranch(repo, targetBranch); resetErr != nil {
			return &types.CloneResult{
				Success: false,
				Error:   fmt.Sprintf("failed to sync branch '%s' after pull error: %v", targetBranch, resetErr),
			}, nil
		}
		g.logger.Info("Recovered by hard resetting branch to remote head", "branch", targetBranch)
	} else if pullErr == git.NoErrAlreadyUpToDate {
		g.logger.Info("Repository is already up to date", "branch", targetBranch)
	} else {
		// Successful pull
		g.logger.Info("Successfully pulled latest changes", "branch", targetBranch)
	}

	// Ensure final state matches remote head to avoid lingering local commits
	if resetErr := g.hardResetBranch(repo, targetBranch); resetErr != nil {
		g.logger.Warn("Failed to perform final hard reset after pull", "branch", targetBranch, "error", resetErr)
	}

	return &types.CloneResult{
		Success:   true,
		ClonePath: clonePath,
	}, nil
}
