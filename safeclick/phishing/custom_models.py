from collections import Counter
from sklearn.utils import resample
import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
import numpy as np
from collections import Counter
from sklearn.base import BaseEstimator, ClassifierMixin

class DecisionTreeClassifierFromScratch(BaseEstimator, ClassifierMixin):
    def __init__(self, max_depth=10, random_state=None):
        self.max_depth = max_depth
        self.random_state = random_state
        self.tree = None

    def fit(self, X, y):
        # Store the unique classes
        self.classes_ = np.unique(y)
        np.random.seed(self.random_state)
        self.tree = self._build_tree(X, y)
        return self  # Return self for Scikit-learn compatibility

    def predict(self, X):
        return np.array([self._traverse_tree(x, self.tree) for x in X])

    def _build_tree(self, X, y, depth=0):
        n_samples, n_features = X.shape
        n_labels = len(np.unique(y))

        # Stopping conditions
        if depth >= self.max_depth or n_labels == 1 or n_samples <= 1:
            return self._leaf_node(y)

        # Find the best split
        best_feature, best_threshold = self._find_best_split(X, y, n_features)

        # If no split is found, return leaf node
        if best_feature is None:
            return self._leaf_node(y)

        # Split the dataset
        left_idxs, right_idxs = self._split(X[:, best_feature], best_threshold)
        if len(left_idxs) == 0 or len(right_idxs) == 0:
          return self._leaf_node(y)
        left_tree = self._build_tree(X[left_idxs, :], y[left_idxs], depth + 1)
        right_tree = self._build_tree(X[right_idxs, :], y[right_idxs], depth + 1)

        return {"feature": best_feature, "threshold": best_threshold, "left": left_tree, "right": right_tree}

    def _leaf_node(self, y):
        label = Counter(y).most_common(1)[0][0]
        return {"label": label}

    def _find_best_split(self, X, y, n_features):
        best_gain = -1
        split_feature, split_threshold = None, None

        for feature in range(n_features):
            thresholds = np.unique(X[:, feature])
            for threshold in thresholds:
                gain = self._information_gain(y, X[:, feature], threshold)

                if gain > best_gain:
                    best_gain = gain
                    split_feature = feature
                    split_threshold = threshold

        return split_feature, split_threshold

    def _information_gain(self, y, feature_values, threshold):
        # Parent Gini
        parent_gini = self._gini(y)

        # Split
        left_idxs, right_idxs = self._split(feature_values, threshold)
        if len(left_idxs) == 0 or len(right_idxs) == 0:
            return 0

        # Weighted Gini of children
        n = len(y)
        n_left, n_right = len(left_idxs), len(right_idxs)
        gini_left, gini_right = self._gini(y[left_idxs]), self._gini(y[right_idxs])
        weighted_gini = (n_left / n) * gini_left + (n_right / n) * gini_right

        # Information Gain
        return parent_gini - weighted_gini

    def _gini(self, y):
        # Vectorized Gini computation
        _, counts = np.unique(y, return_counts=True)
        probabilities = counts / len(y)
        return 1 - np.dot(probabilities, probabilities)


    def _split(self, feature_values, threshold):
        left_idxs = np.where(feature_values <= threshold)[0]
        right_idxs = np.where(feature_values > threshold)[0]
        return left_idxs, right_idxs

    def _traverse_tree(self, x, node):
        if "label" in node:
            return node["label"]

        feature = node["feature"]
        threshold = node["threshold"]

        if x[feature] <= threshold:
            return self._traverse_tree(x, node["left"])
        else:
            return self._traverse_tree(x, node["right"])

import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
from joblib import Parallel, delayed

class GradientBoostingClassifierFromScratch(BaseEstimator, ClassifierMixin):
    def __init__(self, n_estimators=300, learning_rate=0.01, max_depth=10, random_state=None):
        self.n_estimators = n_estimators
        self.learning_rate = learning_rate
        self.max_depth = max_depth
        self.random_state = random_state
        self.trees = []
        self.initial_prediction = None

    from joblib import Parallel, delayed

    def fit(self, X, y):
        np.random.seed(self.random_state)
        self.classes_ = np.unique(y)

        # Initialize predictions with the log odds (logistic regression style)
        y_mean = np.mean(y)
        self.initial_prediction = np.log(y_mean / (1 - y_mean))
        predictions = np.full(y.shape, self.initial_prediction)

        # Parallelized training of trees
        def train_tree(X, residuals, max_depth, random_state):
            tree = DecisionTreeClassifierFromScratch(max_depth=max_depth, random_state=random_state)
            tree.fit(X, residuals > 0)
            return tree

        # Train all trees in parallel
        self.trees = Parallel(n_jobs=-1)(
            delayed(train_tree)(X, y - 1 / (1 + np.exp(-predictions)), self.max_depth, self.random_state)
            for _ in range(self.n_estimators)
        )

        # Update predictions after training trees
        for tree in self.trees:
            predictions += self.learning_rate * np.array(tree.predict(X), dtype=float)

    def predict_proba(self, X):
        # Aggregate predictions from all trees
        predictions = np.full((X.shape[0],), self.initial_prediction)
        for tree in self.trees:
            predictions += self.learning_rate * np.array(tree.predict(X), dtype=float)
        proba = 1 / (1 + np.exp(-predictions))  # Sigmoid for probabilities
        return np.vstack((1 - proba, proba)).T

    def predict(self, X):
        # Return class predictions based on probabilities
        proba = self.predict_proba(X)
        return np.argmax(proba, axis=1)

    def score(self, X, y):
        from sklearn.metrics import accuracy_score
        return accuracy_score(y, self.predict(X))

import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
from collections import Counter
from sklearn.utils import resample

class RandomForestClassifierFromScratch(BaseEstimator, ClassifierMixin):
    def __init__(self, n_estimators=300, max_depth=10, max_features="sqrt", random_state=None):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.max_features = max_features
        self.random_state = random_state
        self.trees = []  # To store individual trees
        self.feature_indices = []  # To store selected feature indices for each tree

    def fit(self, X, y):
        np.random.seed(self.random_state)
        n_samples, n_features = X.shape
        # Store unique class labels
        self.classes_ = np.unique(y)
        # Determine the number of features to sample
        if self.max_features == "sqrt":
            n_features_to_sample = int(np.sqrt(n_features))
        elif self.max_features == "log2":
            n_features_to_sample = int(np.log2(n_features))
        else:
            n_features_to_sample = n_features

        for i in range(self.n_estimators):
            # Bootstrap sampling
            X_sample, y_sample = resample(X, y, random_state=self.random_state)

            # Random feature selection
            feature_indices = np.random.choice(n_features, n_features_to_sample, replace=False)
            self.feature_indices.append(feature_indices)

            # Train a decision tree
            tree = DecisionTreeClassifierFromScratch(max_depth=self.max_depth, random_state=self.random_state)
            tree.fit(X_sample[:, feature_indices], y_sample)
            self.trees.append(tree)

    def predict(self, X):
        # Collect predictions from each tree
        tree_predictions = np.array([
            tree.predict(X[:, feature_indices]) for tree, feature_indices in zip(self.trees, self.feature_indices)
        ])
        # Majority voting
        return np.apply_along_axis(lambda x: Counter(x).most_common(1)[0][0], axis=0, arr=tree_predictions)

    def score(self, X, y):
        from sklearn.metrics import accuracy_score
        return accuracy_score(y, self.predict(X))
