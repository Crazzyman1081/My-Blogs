import { getSortedPostsData } from "@/lib/posts";
import PostCard from "@/components/PostCard";
import styles from "../page.module.css"; // Reuse home styles

export default function Blogs() {
    const allPostsData = getSortedPostsData();
    const blogs = allPostsData.filter(post => !post.title.toLowerCase().includes("writeups"));

    return (
        <div className={styles.container}>
            <header className={styles.header}>
                <h1 className={styles.title}>Reflections & Routes</h1>
                <p className={styles.subtitle}>
                    Rants, Ramblings, and Research.
                </p>
            </header>

            {blogs.length > 0 ? (
                <div className={styles.grid}>
                    {blogs.map((post) => (
                        <PostCard
                            key={post.id}
                            id={post.id}
                            title={post.title}
                            date={post.date}
                            excerpt={post.description || post.excerpt}
                            coverImage={post.coverImage}
                        />
                    ))}
                </div>
            ) : (
                <div className={styles.empty}>
                    <p>No blogs found yet.</p>
                </div>
            )}
        </div>
    );
}
