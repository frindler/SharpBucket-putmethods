﻿using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using SharpBucket.Utility;
using SharpBucket.V2.Pocos;

namespace SharpBucket.V2.EndPoints
{
    /// <summary>
    /// Use this resource to get information associated with an individual repository. 
    /// You can use these calls with public or private repositories. 
    /// Private repositories require the caller to authenticate with an account that has the appropriate authorization.
    /// More info:
    /// https://confluence.atlassian.com/display/BITBUCKET/repository+Resource
    /// </summary>
    public class RepositoryResource : EndPoint
    {
        private readonly string _accountName;
        private readonly string _repoSlugOrName;

        #region Repository Resource

        internal RepositoryResource(RepositoriesAccountResource repositoriesAccountResource, string repoSlugOrName)
            : base(repositoriesAccountResource, repoSlugOrName.ToSlug())
        {
            _repoSlugOrName = repoSlugOrName;
            _accountName = repositoriesAccountResource.AccountName;
        }

        /// <summary>
        /// Returns a single repository.
        /// </summary>
        /// <returns></returns>
        public Repository GetRepository()
        {
            return SharpBucketV2.Get<Repository>(BaseUrl);
        }

        /// <summary>
        /// Returns a single repository.
        /// </summary>
        /// <param name="token">The cancellation token</param>
        /// <returns></returns>
        public Task<Repository> GetRepositoryAsync(CancellationToken token = default)
        {
            return SharpBucketV2.GetAsync<Repository>(BaseUrl, token);
        }

        /// <summary>
        /// Removes a repository.  
        /// </summary>
        /// <returns></returns>
        public void DeleteRepository()
        {
            SharpBucketV2.Delete(BaseUrl);
        }

        /// <summary>
        /// Removes a repository.  
        /// </summary>
        /// <param name="token">The cancellation token</param>
        /// <returns></returns>
        public Task DeleteRepositoryAsync(CancellationToken token = default)
        {
            return SharpBucketV2.DeleteAsync(BaseUrl, token);
        }

        /// <summary>
        /// Creates a new repository.
        /// </summary>
        /// <param name="repository">The repository to create.</param>
        /// <returns>The created repository.</returns>
        public Repository PostRepository(Repository repository)
        {
            return SharpBucketV2.Post(repository, BaseUrl);
        }

        /// <summary>
        /// Creates a new repository.
        /// </summary>
        /// <param name="repository">The repository to create.</param>
        /// <param name="token">The cancellation token</param>
        /// <returns>The created repository.</returns>
        public Task<Repository> PostRepositoryAsync(Repository repository, CancellationToken token = default)
        {
            return SharpBucketV2.PostAsync(repository, BaseUrl, token);
        }

        /// <summary>
        /// Updates a repository.
        /// </summary>
        /// <param name="repository">The repository to update.</param>
        /// <returns>The updated repository.</returns>
        public Repository PutRepository(Repository repository)
        {
            return SharpBucketV2.Put(repository, BaseUrl);
        }

        /// <summary>
        /// Updates a repository.
        /// </summary>
        /// <param name="repository">The repository to update.</param>
        /// <param name="token">The cancellation token</param>
        /// <returns>The updated repository.</returns>
        public Task<Repository> PutRepositoryAsync(Repository repository, CancellationToken token = default)
        {
            return SharpBucketV2.PutAsync(repository, BaseUrl, token);
        }

        /// <summary>
        /// List accounts watching a repository. 
        /// </summary>
        /// <returns></returns>
        public List<UserInfo> ListWatchers()
        {
            return ListWatchers(0);
        }

        /// <summary>
        /// List accounts watching a repository.
        /// </summary>
        /// <param name="max">The maximum number of items to return. 0 returns all items.</param>
        public List<UserInfo> ListWatchers(int max)
        {
            return SharpBucketV2.GetPaginatedValues<UserInfo>(BaseUrl + "/watchers", max);
        }

        /// <summary>
        /// Enumerate accounts watching a repository.
        /// </summary>
        /// <param name="pageLen">The length of a page. If not defined the default page length will be used.</param>
        public IEnumerable<UserInfo> EnumerateWatchers(int? pageLen = null)
        {
            return SharpBucketV2.EnumeratePaginatedValues<UserInfo>(BaseUrl + "/watchers", null, pageLen);
        }

#if CS_8
        /// <summary>
        /// Enumerate accounts watching a repository asynchronously, doing requests page by page.
        /// </summary>
        /// <param name="pageLen">The length of a page. If not defined the default page length will be used.</param>
        /// <param name="token">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
        public IAsyncEnumerable<UserInfo> EnumerateWatchersAsync(int? pageLen = null, CancellationToken token = default)
        {
            return SharpBucketV2.EnumeratePaginatedValuesAsync<UserInfo>(BaseUrl + "/watchers", null, pageLen, token);
        }
#endif

        /// <summary>
        /// List repository forks, This call returns a repository object for each fork.
        /// </summary>
        /// <returns></returns>
        public List<Repository> ListForks()
        {
            return ListForks(0);
        }

        /// <summary>
        /// List repository forks, This call returns a repository object for each fork.
        /// </summary>
        /// <param name="max">The maximum number of items to return. 0 returns all items.</param>
        public List<Repository> ListForks(int max)
        {
            return GetPaginatedValues<Repository>(BaseUrl + "/forks", max);
        }

        /// <summary>
        /// Enumerate repository forks, This call returns a repository object for each fork.
        /// </summary>
        /// <param name="pageLen">The length of a page. If not defined the default page length will be used.</param>
        public IEnumerable<Repository> EnumerateForks(int? pageLen = null)
        {
            return SharpBucketV2.EnumeratePaginatedValues<Repository>(BaseUrl + "/forks", pageLen: pageLen);
        }

#if CS_8
        /// <summary>
        /// Enumerate repository forks asynchronously, doing requests page by page.
        /// This call returns a repository object for each fork.
        /// </summary>
        /// <param name="pageLen">The length of a page. If not defined the default page length will be used.</param>
        /// <param name="token">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
        public IAsyncEnumerable<Repository> EnumerateForksAsync(int? pageLen = null, CancellationToken token = default)
        {
            return SharpBucketV2.EnumeratePaginatedValuesAsync<Repository>(BaseUrl + "/forks", new Dictionary<string, object>(), pageLen, token);
        }
#endif

        #endregion

        #region BranchResource

        private BranchResource _branchesResource;

        public BranchResource BranchesResource
            => this._branchesResource ??= new BranchResource(this);

        #endregion

        #region Pull Requests Resource

        /// <summary>
        /// Manage pull requests for a repository. Use this resource to perform CRUD (create/read/update/delete) operations on a pull request. 
        /// This resource allows you to manage the attributes of a pull request also. For example, you can list the commits 
        /// or reviewers associated with a pull request. You can also accept or decline a pull request with this resource. 
        /// Finally, you can use this resource to manage the comments on a pull request as well.
        /// More info:
        /// https://developer.atlassian.com/bitbucket/api/2/reference/resource/repositories/%7Bworkspace%7D/%7Brepo_slug%7D/pullrequests
        /// </summary>
        /// <returns></returns>
        public PullRequestsResource PullRequestsResource()
        {
            return new PullRequestsResource(this);
        }

        #endregion

        #region Branch Model Resource

        private BranchingModelResource _branchingModelResource;

        /// <summary>
        /// Gets the resource to manage the branching model for this repository.
        /// </summary>
        public BranchingModelResource BranchingModelResource
            => this._branchingModelResource ??= new BranchingModelResource(this);

        #endregion

        #region Branch Restrictions Resource

        /// More info:
        /// https://developer.atlassian.com/bitbucket/api/2/reference/resource/repositories/%7Bworkspace%7D/%7Brepo_slug%7D/branch-restrictions#get
        /// <summary>
        /// List the information associated with a repository's branch restrictions. 
        /// </summary>
        public List<BranchRestriction> ListBranchRestrictions()
            => ListBranchRestrictions(new ListBranchRestrictionsParameters());

        /// <summary>
        /// List the information associated with a repository's branch restrictions. 
        /// </summary>
        /// <param name="parameters">Query parameters that can be used to filter the results.</param>
        public List<BranchRestriction> ListBranchRestrictions(
            ListBranchRestrictionsParameters parameters)
        {
            _ = parameters ?? throw new ArgumentNullException(nameof(parameters));
            return GetPaginatedValues<BranchRestriction>(BaseUrl + "/branch-restrictions", parameters.Max, parameters.ToDictionary());
        }

        /// <summary>
        /// Enumerate the information associated with a repository's branch restrictions.
        /// Requests will be done page by page while enumerating.
        /// </summary>
        public IEnumerable<BranchRestriction> EnumerateBranchRestrictions()
            => EnumerateBranchRestrictions(new EnumerateBranchRestrictionsParameters());

        /// <summary>
        /// Enumerate the information associated with a repository's branch restrictions.
        /// Requests will be done page by page while enumerating.
        /// </summary>
        /// <param name="parameters">Query parameters that can be used to filter the results.</param>
        public IEnumerable<BranchRestriction> EnumerateBranchRestrictions(
            EnumerateBranchRestrictionsParameters parameters)
        {
            _ = parameters ?? throw new ArgumentNullException(nameof(parameters));
            return SharpBucketV2.EnumeratePaginatedValues<BranchRestriction>(
                BaseUrl + "/branch-restrictions",
                parameters.ToDictionary(),
                parameters.PageLen);
        }

#if CS_8
        /// <summary>
        /// Enumerate the information associated with a repository's branch restrictions asynchronously,
        /// doing requests page by page.
        /// </summary>
        /// <param name="token">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
        public IAsyncEnumerable<BranchRestriction> EnumerateBranchRestrictionsAsync(
            CancellationToken token = default)
            => EnumerateBranchRestrictionsAsync(new EnumerateBranchRestrictionsParameters(), token);

        /// <summary>
        /// Enumerate the information associated with a repository's branch restrictions asynchronously,
        /// doing requests page by page.
        /// </summary>
        /// <param name="parameters">Query parameters that can be used to filter the results.</param>
        /// <param name="token">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
        public IAsyncEnumerable<BranchRestriction> EnumerateBranchRestrictionsAsync(
            EnumerateBranchRestrictionsParameters parameters,
            CancellationToken token = default)
        {
            _ = parameters ?? throw new ArgumentNullException(nameof(parameters));
            return SharpBucketV2.EnumeratePaginatedValuesAsync<BranchRestriction>(
                BaseUrl + "/branch-restrictions",
                parameters.ToDictionary(),
                parameters.PageLen,
                token);
        }
#endif

        /// <summary>
        /// Creates restrictions for the specified repository. You should specify a Content-Header with this call. 
        /// </summary>
        /// <param name="restriction">The branch restriction.</param>
        /// <returns></returns>
        public BranchRestriction PostBranchRestriction(BranchRestriction restriction)
        {
            return SharpBucketV2.Post(restriction, BaseUrl + "/branch-restrictions");
        }

        /// <summary>
        /// Creates restrictions for the specified repository. You should specify a Content-Header with this call. 
        /// </summary>
        /// <param name="restriction">The branch restriction.</param>
        /// <param name="token">The cancellation token</param>
        /// <returns></returns>
        public Task<BranchRestriction> PostBranchRestrictionAsync(BranchRestriction restriction, CancellationToken token = default)
        {
            return SharpBucketV2.PostAsync(restriction, BaseUrl + "/branch-restrictions", token);
        }

        /// <summary>
        /// Gets the information associated with specific restriction. 
        /// </summary>
        /// <param name="restrictionId">The restriction's identifier.</param>
        /// <returns></returns>
        public BranchRestriction GetBranchRestriction(int restrictionId)
        {
            return SharpBucketV2.Get<BranchRestriction>(BaseUrl + $"/branch-restrictions/{restrictionId}");
        }

        /// <summary>
        /// Gets the information associated with specific restriction. 
        /// </summary>
        /// <param name="restrictionId">The restriction's identifier.</param>
        /// <param name="token">The cancellation token</param>
        /// <returns></returns>
        public Task<BranchRestriction> GetBranchRestrictionAsync(int restrictionId, CancellationToken token = default)
        {
            return SharpBucketV2.GetAsync<BranchRestriction>(BaseUrl + $"/branch-restrictions/{restrictionId}", token);
        }

        /// <summary>
        /// Updates a specific branch restriction. You cannot change the kind value with this call. 
        /// </summary>
        /// <param name="restriction">The branch restriction.</param>
        /// <returns></returns>
        public BranchRestriction PutBranchRestriction(BranchRestriction restriction)
        {
            return SharpBucketV2.Put(restriction, BaseUrl + $"/branch-restrictions/{restriction.id}");
        }

        /// <summary>
        /// Updates a specific branch restriction. You cannot change the kind value with this call. 
        /// </summary>
        /// <param name="restriction">The branch restriction.</param>
        /// <param name="token">The cancellation token</param>
        /// <returns></returns>
        public Task<BranchRestriction> PutBranchRestrictionAsync(BranchRestriction restriction, CancellationToken token = default)
        {
            return SharpBucketV2.PutAsync(restriction, BaseUrl + $"/branch-restrictions/{restriction.id}", token);
        }

        /// <summary>
        /// Deletes the specified restriction.  
        /// </summary>
        /// <param name="restrictionId">The restriction's identifier.</param>
        /// <returns></returns>
        public void DeleteBranchRestriction(int restrictionId)
        {
            SharpBucketV2.Delete(BaseUrl + $"/branch-restrictions/{restrictionId}");
        }

        /// <summary>
        /// Deletes the specified restriction.  
        /// </summary>
        /// <param name="restrictionId">The restriction's identifier.</param>
        /// <param name="token">The cancellation token</param>
        /// <returns></returns>
        public Task DeleteBranchRestrictionAsync(int restrictionId, CancellationToken token = default)
        {
            return SharpBucketV2.DeleteAsync(BaseUrl + $"/branch-restrictions/{restrictionId}", token);
        }

        #endregion

        #region Diff Resource

        /// More info:
        /// https://confluence.atlassian.com/display/BITBUCKET/diff+Resource
        /// <summary>
        /// Gets the diff for the current repository.
        /// </summary>
        /// <param name="spec">The diff spec (e.g., de3f2..78ab1).</param>
        /// <returns></returns>
        public string GetDiff(string spec)
            => GetDiff(spec, new DiffParameters());

        /// <summary>
        /// Gets the diff for the current repository.
        /// </summary>
        /// <param name="spec">The diff spec (e.g., de3f2..78ab1).</param>
        /// <param name="parameters">Parameters for the diff.</param>
        /// <returns></returns>
        public string GetDiff(string spec, DiffParameters parameters)
        {
            return SharpBucketV2.Get(BaseUrl + $"/diff/{spec}", parameters.ToDictionary());
        }

        /// More info:
        /// https://confluence.atlassian.com/display/BITBUCKET/diff+Resource
        /// <summary>
        /// Gets the diff for the current repository.
        /// </summary>
        /// <param name="spec">The diff spec (e.g., de3f2..78ab1).</param>
        /// <param name="token">The cancellation token</param>
        /// <returns></returns>
        public Task<string> GetDiffAsync(string spec, CancellationToken token = default)
            => GetDiffAsync(spec, new DiffParameters(), token);

        /// <summary>
        /// Gets the diff for the current repository.
        /// </summary>
        /// <param name="spec">The diff spec (e.g., de3f2..78ab1).</param>
        /// <param name="parameters">Parameters for the diff.</param>
        /// <param name="token">The cancellation token</param>
        /// <returns></returns>
        public Task<string> GetDiffAsync(string spec, DiffParameters parameters, CancellationToken token = default)
        {
            return SharpBucketV2.GetAsync(BaseUrl + $"/diff/{spec}", parameters.ToDictionary(), token);
        }

        /// <summary>
        /// Gets the patch for an individual specification. 
        /// </summary>
        /// <param name="spec">The patch spec.</param>
        /// <returns></returns>
        public string GetPatch(string spec)
        {
            return SharpBucketV2.Get(BaseUrl + $"/patch/{spec}");
        }

        /// <summary>
        /// Gets the patch for an individual specification. 
        /// </summary>
        /// <param name="spec">The patch spec.</param>
        /// <param name="token">The cancellation token</param>
        /// <returns></returns>
        public Task<string> GetPatchAsync(string spec, CancellationToken token = default)
        {
            return SharpBucketV2.GetAsync(BaseUrl + $"/patch/{spec}", token);
        }

        #endregion

        #region Commit resource

        public CommitResource CommitResource(string revision)
        {
            return new CommitResource(this, revision);
        }

        #endregion

        #region Commits resource

        /// More info:
        /// https://developer.atlassian.com/bitbucket/api/2/reference/resource/repositories/%7Bworkspace%7D/%7Brepo_slug%7D/commits#get
        /// <summary>
        /// Gets the commit information associated with a repository.
        /// By default, this call returns all the commits across all branches, bookmarks, and tags.
        /// The newest commit is first.
        /// </summary>
        /// <param name="branchOrTag">The branch or tag to get, for example, master or default.</param>
        /// <param name="max">Values greater than 0 will set a maximum number of records to return. 0 or less returns all.</param>
        public List<Commit> ListCommits(string branchOrTag = null, int max = 0)
            => ListCommits(branchOrTag, new ListCommitsParameters { Max = max });

        /// <summary>
        /// Gets the commit information associated with a repository.
        /// By default, this call returns all the commits across all branches, bookmarks, and tags.
        /// The newest commit is first.
        /// </summary>
        /// <param name="commitsParameters">Parameters that allow to filter the commits to return.</param>
        public List<Commit> ListCommits(ListCommitsParameters commitsParameters)
            => ListCommits(null, commitsParameters);

        /// <summary>
        /// Gets the commit information associated with a repository in a specified branch.
        /// The newest commit is first.
        /// </summary>
        /// <param name="branchOrTag">The branch or tag to get, for example, master or default.</param>
        /// <param name="commitsParameters">Optional parameters that allow to filter the commits to return.</param>
        public List<Commit> ListCommits(string branchOrTag, ListCommitsParameters commitsParameters)
        {
            var overrideUrl = BaseUrl + "/commits";
            if (!string.IsNullOrEmpty(branchOrTag))
            {
                overrideUrl += "/" + branchOrTag;
            }

            return GetPaginatedValues<Commit>(overrideUrl, commitsParameters.Max, commitsParameters.ToDictionary());
        }

        /// <summary>
        /// Enumerate the commits information associated with a repository.
        /// By default, this call returns all the commits across all branches, bookmarks, and tags.
        /// The newest commit is first.
        /// </summary>
        /// <param name="branchOrTag">The branch or tag to get, for example, master or default.</param>
        public IEnumerable<Commit> EnumerateCommits(string branchOrTag = null)
            => EnumerateCommits(branchOrTag, new EnumerateCommitsParameters());

        /// <summary>
        /// Enumerate the commit information associated with a repository.
        /// By default, this call returns all the commits across all branches, bookmarks, and tags.
        /// The newest commit is first.
        /// </summary>
        /// <param name="commitsParameters">Parameters that allow to filter the commits to return.</param>
        public IEnumerable<Commit> EnumerateCommits(EnumerateCommitsParameters commitsParameters)
             => EnumerateCommits(null, commitsParameters);

        /// <summary>
        /// Enumerate the commit information associated with a repository in a specified branch.
        /// The newest commit is first.
        /// </summary>
        /// <param name="branchOrTag">The branch or tag to get, for example, master or default.</param>
        /// <param name="commitsParameters">Optional parameters that allow to filter the commits to return.</param>
        public IEnumerable<Commit> EnumerateCommits(string branchOrTag, EnumerateCommitsParameters commitsParameters)
        {
            var overrideUrl = BaseUrl + "/commits";
            if (!string.IsNullOrEmpty(branchOrTag))
            {
                overrideUrl += "/" + branchOrTag;
            }

            return SharpBucketV2.EnumeratePaginatedValues<Commit>(
                overrideUrl,
                commitsParameters.ToDictionary(),
                commitsParameters.PageLen);
        }

#if CS_8
        /// <summary>
        /// Enumerate the commits information associated with a repository.
        /// By default, this call returns all the commits across all branches, bookmarks, and tags.
        /// The newest commit is first.
        /// </summary>
        /// /// <param name="token">The cancellation token</param>
        public IAsyncEnumerable<Commit> EnumerateCommitsAsync(CancellationToken token = default)
            => EnumerateCommitsAsync(null, new EnumerateCommitsParameters(), token);

        /// <summary>
        /// Enumerate the commits information associated with a repository in a specified branch.
        /// The newest commit is first.
        /// </summary>
        /// <param name="branchOrTag">The branch or tag to get, for example, master or default.</param>
        /// <param name="token">The cancellation token</param>
        public IAsyncEnumerable<Commit> EnumerateCommitsAsync(string branchOrTag, CancellationToken token = default)
            => EnumerateCommitsAsync(branchOrTag, new EnumerateCommitsParameters(), token);

        /// <summary>
        /// Enumerate the commit information associated with a repository.
        /// By default, this call returns all the commits across all branches, bookmarks, and tags.
        /// The newest commit is first.
        /// </summary>
        /// <param name="commitsParameters">Parameters that allow to filter the commits to return.</param>
        /// <param name="token">The cancellation token</param>
        public IAsyncEnumerable<Commit> EnumerateCommitsAsync(EnumerateCommitsParameters commitsParameters, CancellationToken token = default)
            => EnumerateCommitsAsync(null, commitsParameters, token);

        /// <summary>
        /// Enumerate the commit information associated with a repository in a specified branch.
        /// The newest commit is first.
        /// </summary>
        /// <param name="branchOrTag">The branch or tag to get, for example, master or default.</param>
        /// <param name="commitsParameters">Optional parameters that allow to filter the commits to return.</param>
        /// <param name="token">The cancellation token</param>
        public IAsyncEnumerable<Commit> EnumerateCommitsAsync(string branchOrTag, EnumerateCommitsParameters commitsParameters, CancellationToken token = default)
        {
            var overrideUrl = BaseUrl + "/commits";
            if (!string.IsNullOrEmpty(branchOrTag))
            {
                overrideUrl += "/" + branchOrTag;
            }

            return SharpBucketV2.EnumeratePaginatedValuesAsync<Commit>(overrideUrl, commitsParameters.ToDictionary(), commitsParameters.PageLen, token);
        }
#endif

        /// <summary>
        /// Gets the information associated with an individual commit. 
        /// </summary>
        /// <param name="revision">The SHA1 of the commit.</param>
        /// <returns></returns>
        public Commit GetCommit(string revision)
        {
            var overrideUrl = BaseUrl + $"/commit/{revision}";
            return SharpBucketV2.Get<Commit>(overrideUrl);
        }

        /// <summary>
        /// Gets the information associated with an individual commit. 
        /// </summary>
        /// <param name="revision">The SHA1 of the commit.</param>
        /// <param name="token">The cancellation token</param>
        /// <returns></returns>
        public Task<Commit> GetCommitAsync(string revision, CancellationToken token = default)
        {
            var overrideUrl = BaseUrl + $"/commit/{revision}";
            return SharpBucketV2.GetAsync<Commit>(overrideUrl, token);
        }

        /// <summary>
        /// Give your approval on a commit.  
        /// You can only approve a comment on behalf of the authenticated account.  This returns the participant object for the current user.
        /// </summary>
        /// <param name="revision">The SHA1 of the commit.</param>
        /// <returns></returns>
        public UserRole ApproveCommit(string revision)
        {
            var overrideUrl = BaseUrl + $"/commit/{revision}/approve";
            return SharpBucketV2.Post<UserRole>(null, overrideUrl);
        }

        /// <summary>
        /// Give your approval on a commit.  
        /// You can only approve a comment on behalf of the authenticated account.  This returns the participant object for the current user.
        /// </summary>
        /// <param name="revision">The SHA1 of the commit.</param>
        /// <param name="token">The cancellation token</param>
        /// <returns></returns>
        public Task<UserRole> ApproveCommitAsync(string revision, CancellationToken token = default)
        {
            var overrideUrl = BaseUrl + $"/commit/{revision}/approve";
            return SharpBucketV2.PostAsync<UserRole>(null, overrideUrl, token);
        }

        /// <summary>
        /// Revoke your approval of a commit. You can remove approvals on behalf of the authenticated account. 
        /// </summary>
        /// <param name="revision">The SHA1 of the commit.</param>
        /// <returns></returns>
        public void DeleteCommitApproval(string revision)
        {
            var overrideUrl = BaseUrl + $"/commit/{revision}/approve";
            SharpBucketV2.Delete(overrideUrl);
        }

        /// <summary>
        /// Revoke your approval of a commit. You can remove approvals on behalf of the authenticated account. 
        /// </summary>
        /// <param name="revision">The SHA1 of the commit.</param>
        /// <param name="token">The cancellation token</param>
        /// <returns></returns>
        public Task DeleteCommitApprovalAsync(string revision, CancellationToken token = default)
        {
            var overrideUrl = BaseUrl + $"/commit/{revision}/approve";
            return SharpBucketV2.DeleteAsync(overrideUrl, token);
        }

        /// <summary>
        /// Creates a new build status against the specified commit. If the specified key already exists, the existing status object will be overwritten.
        /// </summary>
        /// <param name="revision">The SHA1 of the commit</param>
        /// <param name="buildInfo">The new commit status object</param>
        /// <returns></returns>
        public BuildInfo AddNewBuildStatus(string revision, BuildInfo buildInfo)
        {
            var overrideUrl = BaseUrl + $"/commit/{revision}/statuses/build";
            return SharpBucketV2.Post(buildInfo, overrideUrl);
        }

        /// <summary>
        /// Creates a new build status against the specified commit. If the specified key already exists, the existing status object will be overwritten.
        /// </summary>
        /// <param name="revision">The SHA1 of the commit</param>
        /// <param name="buildInfo">The new commit status object</param>
        /// <param name="token">The cancellation token</param>
        /// <returns></returns>
        public Task<BuildInfo> AddNewBuildStatusAsync(string revision, BuildInfo buildInfo, CancellationToken token = default)
        {
            var overrideUrl = BaseUrl + $"/commit/{revision}/statuses/build";
            return SharpBucketV2.PostAsync(buildInfo, overrideUrl, token);
        }

        /// <summary>
        /// Returns the specified build status for a commit.
        /// </summary>
        /// <param name="revision">The SHA1 of the commit</param>
        /// <param name="key">The build status' unique key</param>
        /// <returns></returns>
        public BuildInfo GetBuildStatusInfo(string revision, string key)
        {
            var overrideUrl = BaseUrl + $"/commit/{revision}/statuses/build/{key}";
            return SharpBucketV2.Get<BuildInfo>(overrideUrl);
        }

        /// <summary>
        /// Returns the specified build status for a commit.
        /// </summary>
        /// <param name="revision">The SHA1 of the commit</param>
        /// <param name="key">The build status' unique key</param>
        /// <param name="token">The cancellation token</param>
        public Task<BuildInfo> GetBuildStatusInfoAsync(string revision, string key, CancellationToken token = default)
        {
            var overrideUrl = BaseUrl + $"/commit/{revision}/statuses/build/{key}";
            return SharpBucketV2.GetAsync<BuildInfo>(overrideUrl, token);
        }

        /// <summary>
        /// Used to update the current status of a build status object on the specific commit.
        /// </summary>
        /// <param name="revision">The SHA1 of the commit</param>
        /// <param name="key">The build status' unique key</param>
        /// <param name="buildInfo">The new commit status object</param>
        /// <remarks>
        /// This operation can also be used to change other properties of the build status: state, name, description, url, refname.
        /// The key cannot be changed.
        /// </remarks>
        public BuildInfo ChangeBuildStatusInfo(string revision, string key, BuildInfo buildInfo)
        {
            var overrideUrl = BaseUrl + $"/commit/{revision}/statuses/build/{key}";
            return SharpBucketV2.Put(buildInfo, overrideUrl);
        }

        /// <summary>
        /// Used to update the current status of a build status object on the specific commit.
        /// </summary>
        /// <param name="revision">The SHA1 of the commit</param>
        /// <param name="key">The build status' unique key</param>
        /// <param name="buildInfo">The new commit status object</param>
        /// <param name="token">The cancellation token</param>
        /// <remarks>
        /// This operation can also be used to change other properties of the build status: state, name, description, url, refname.
        /// The key cannot be changed.
        /// </remarks>
        public Task<BuildInfo> ChangeBuildStatusInfoAsync(string revision, string key, BuildInfo buildInfo, CancellationToken token = default)
        {
            var overrideUrl = BaseUrl + $"/commit/{revision}/statuses/build/{key}";
            return SharpBucketV2.PutAsync(buildInfo, overrideUrl, token);
        }

        #endregion

        #region Default Reviewer Resource

        /// <summary>
        /// Adds a user as the default review for pull requests on a repository.
        /// </summary>
        /// <param name="targetUsername">The user to add as the default reviewer.</param>
        /// <returns></returns>
        public void PutDefaultReviewer(string targetUsername)
        {
            var overrideUrl = BaseUrl + $"/default-reviewers/{targetUsername}";
            SharpBucketV2.Put(new object(), overrideUrl);
        }

        /// <summary>
        /// Adds a user as the default review for pull requests on a repository.
        /// </summary>
        /// <param name="targetUsername">The user to add as the default reviewer.</param>
        /// <param name="token">The cancellation token</param>
        /// <returns></returns>
        public Task PutDefaultReviewerAsync(string targetUsername, CancellationToken token = default)
        {
            var overrideUrl = BaseUrl + $"/default-reviewers/{targetUsername}";
            return SharpBucketV2.PutAsync(new object(), overrideUrl, token: token);
        }

        #endregion

        #region Deployments Config resource

        private DeploymentsConfigResource _deploymentsConfigResource;

        public DeploymentsConfigResource DeploymentsConfigResource
            => this._deploymentsConfigResource ??= new DeploymentsConfigResource(this);

        #endregion

        #region Environments resource

        private EnvironmentsResource _environmentsResource;

        public EnvironmentsResource EnvironmentsResource
            => this._environmentsResource ??= new EnvironmentsResource(this);

        #endregion

        #region Src resource

        public string GetMainBranchRevision()
        {
            var repoPath = $"{_accountName.GuidOrValue()}/{_repoSlugOrName.ToSlug()}";
            var rootSrcPath = "src/";

            try
            {
                // calling the src endpoint redirect to the hash of the last commit of the main branch
                // https://developer.atlassian.com/bitbucket/api/2/reference/resource/repositories/%7Busername%7D/%7Brepo_slug%7D/src#get
                var redirectLocation = this.GetSrcRootRedirectLocation(rootSrcPath);
                return redirectLocation.Segments[redirectLocation.Segments.Length - 1].TrimEnd('/');
            }
            catch (BitbucketV2Exception e) when (e.HttpStatusCode == HttpStatusCode.NotFound)
            {
                // mimic the error that bitbucket send when we perform calls on src endpoint with a revision name
                var errorResponse = new ErrorResponse { type = "Error", error = new Error { message = $"Repository {repoPath} not found" } };
                throw new BitbucketV2Exception(HttpStatusCode.NotFound, errorResponse);
            }
        }

        public async Task<string> GetMainBranchRevisionAsync(CancellationToken token = default)
        {
            var repoPath = $"{_accountName.GuidOrValue()}/{_repoSlugOrName.ToSlug()}";
            var rootSrcPath = "src/";

            try
            {
                // calling the src endpoint redirect to the hash of the last commit of the main branch
                // https://developer.atlassian.com/bitbucket/api/2/reference/resource/repositories/%7Busername%7D/%7Brepo_slug%7D/src#get
                var redirectLocation = await this.GetSrcRootRedirectLocationAsync(rootSrcPath, token);
                return redirectLocation.Segments[redirectLocation.Segments.Length - 1].TrimEnd('/');
            }
            catch (BitbucketV2Exception e) when (e.HttpStatusCode == HttpStatusCode.NotFound)
            {
                // mimic the error that bitbucket send when we perform calls on src endpoint with a revision name
                var errorResponse = new ErrorResponse { type = "Error", error = new Error { message = $"Repository {repoPath} not found" } };
                throw new BitbucketV2Exception(HttpStatusCode.NotFound, errorResponse);
            }
        }

        private Uri GetSrcRootRedirectLocation(string srcResourcePath)
        {
            var overrideUrl = UrlHelper.ConcatPathSegments(BaseUrl, srcResourcePath);
            return SharpBucketV2.GetRedirectLocation(overrideUrl, new { format = "meta" });
        }

        private Task<Uri> GetSrcRootRedirectLocationAsync(string srcResourcePath, CancellationToken token)
        {
            var overrideUrl = UrlHelper.ConcatPathSegments(BaseUrl, srcResourcePath);
            return SharpBucketV2.GetRedirectLocationAsync(overrideUrl, new { format = "meta" }, token);
        }

        /// <summary>
        /// Get a Src resource that allows to browse the content of the repository
        /// </summary>
        /// <remarks>
        /// If revision is null a non async request will occurs.
        /// if you want a fully async experience, you should do yourself an explicit call to <see cref="GetMainBranchRevisionAsync(CancellationToken)"/>
        /// and then provide the result in the <paramref name="revision"/> parameter.
        /// </remarks>
        /// <param name="revision">The name of the revision to browse. This may be a commit hash, a branch name, a tag name, or null to target the last commit of the main branch.</param>
        /// <param name="path">An optional path to a sub directory if you want to start to browse somewhere else that at the root path.</param>
        public SrcResource SrcResource(string revision = null, string path = null)
        {
            return new SrcResource(this, revision, path);
        }

        #endregion

        #region tags resource

        private TagsResource _tagsResource;

        /// <summary>
        /// Gets the resource that allow to manage tags for this repository.
        /// </summary>
        public TagsResource TagsResource
            => this._tagsResource ??= new TagsResource(this);

        #endregion

        #region Issues Resource

        /// <summary>
        /// Gets the resource that allow to manage issues for this repository.
        /// </summary>
        public IssuesResource IssuesResource()
        {
            return new IssuesResource(this);
        }

        #endregion
    }
}