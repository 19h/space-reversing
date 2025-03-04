use serde::{Deserialize, Serialize};

/// 3D vector representation
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Vector3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

//------------------------------------------------------------------------------
// Basic Vector Operations
//------------------------------------------------------------------------------

impl Vector3 {
    /// Create a new vector with the given components
    pub fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }

    /// Calculate the Euclidean distance between two vectors
    pub fn distance(&self, other: &Vector3) -> f64 {
        ((self.x - other.x).powi(2) + 
         (self.y - other.y).powi(2) + 
         (self.z - other.z).powi(2)).sqrt()
    }
    
    /// Return a normalized (unit length) version of this vector
    pub fn normalized(&self) -> Self {
        let magnitude = (self.x.powi(2) + self.y.powi(2) + self.z.powi(2)).sqrt();
        if magnitude < 1e-6 {
            return *self; // Return unchanged if near-zero magnitude
        }
        Self {
            x: self.x / magnitude,
            y: self.y / magnitude,
            z: self.z / magnitude,
        }
    }

    /// Create a new vector with all components set to zero
    pub fn zero() -> Self {
        Self { x: 0.0, y: 0.0, z: 0.0 }
    }
    
    /// Create a unit vector along the x-axis
    pub fn unit_x() -> Self {
        Self { x: 1.0, y: 0.0, z: 0.0 }
    }
    
    /// Create a unit vector along the y-axis
    pub fn unit_y() -> Self {
        Self { x: 0.0, y: 1.0, z: 0.0 }
    }
    
    /// Create a unit vector along the z-axis
    pub fn unit_z() -> Self {
        Self { x: 0.0, y: 0.0, z: 1.0 }
    }
    
    /// Calculate the magnitude (length) of the vector
    pub fn magnitude(&self) -> f64 {
        (self.x.powi(2) + self.y.powi(2) + self.z.powi(2)).sqrt()
    }
    
    /// Calculate the squared magnitude (avoids the sqrt calculation)
    pub fn magnitude_squared(&self) -> f64 {
        self.x.powi(2) + self.y.powi(2) + self.z.powi(2)
    }
    
    /// Calculate the dot product with another vector
    pub fn dot(&self, other: &Vector3) -> f64 {
        self.x * other.x + self.y * other.y + self.z * other.z
    }
    
    /// Calculate the cross product with another vector
    pub fn cross(&self, other: &Vector3) -> Self {
        Self {
            x: self.y * other.z - self.z * other.y,
            y: self.z * other.x - self.x * other.z,
            z: self.x * other.y - self.y * other.x,
        }
    }
    
    /// Scale the vector by a scalar value
    pub fn scale(&self, scalar: f64) -> Self {
        Self {
            x: self.x * scalar,
            y: self.y * scalar,
            z: self.z * scalar,
        }
    }
    
    /// Negate all components of the vector
    pub fn negate(&self) -> Self {
        Self {
            x: -self.x,
            y: -self.y,
            z: -self.z,
        }
    }

    /// Orthogonalize a vector relative to another using Gram-Schmidt
    pub fn orthogonalize(&self, base: &Vector3) -> Self {
        self - &self.project_onto(base)
    }

    /// Gram-Schmidt orthonormalization given two vectors (creates an orthonormal basis)
    pub fn orthonormal_basis(a: &Vector3, b: &Vector3) -> [Vector3; 3] {
        let u1 = a.normalized();
        let u2 = b.orthogonalize(&u1).normalized();
        let u3 = u1.cross(&u2);
        [u1, u2, u3]
    }

    /// Calculate determinant of three vectors (3x3 matrix formed by vectors as columns)
    pub fn determinant(a: &Vector3, b: &Vector3, c: &Vector3) -> f64 {
        a.x * (b.y * c.z - b.z * c.y) -
        a.y * (b.x * c.z - b.z * c.x) +
        a.z * (b.x * c.y - b.y * c.x)
    }

    /// Multiply vector by a 3x3 matrix (useful for rotations and linear transforms)
    pub fn transform_matrix3(&self, m: [[f64; 3]; 3]) -> Self {
        Self {
            x: m[0][0]*self.x + m[0][1]*self.y + m[0][2]*self.z,
            y: m[1][0]*self.x + m[1][1]*self.y + m[1][2]*self.z,
            z: m[2][0]*self.x + m[2][1]*self.y + m[2][2]*self.z,
        }
    }

    /// Multiply vector by a 4x4 affine transformation matrix
    pub fn transform_matrix4(&self, m: [[f64; 4]; 4]) -> Self {
        Self {
            x: m[0][0]*self.x + m[0][1]*self.y + m[0][2]*self.z + m[0][3],
            y: m[1][0]*self.x + m[1][1]*self.y + m[1][2]*self.z + m[1][3],
            z: m[2][0]*self.x + m[2][1]*self.y + m[2][2]*self.z + m[2][3],
        }
    }

    /// Robust method to find a vector orthogonal to this one (numerically stable)
    pub fn robust_perpendicular(&self) -> Self {
        if self.x.abs() > self.y.abs() {
            Self::new(-self.z, 0.0, self.x).normalized()
        } else {
            Self::new(0.0, self.z, -self.y).normalized()
        }
    }

    /// Swap x and y components, keeping z the same
    pub fn yxz(&self) -> Self {
        Self { x: self.y, y: self.x, z: self.z }
    }

    /// Swap x and z components, keeping y the same
    pub fn zyx(&self) -> Self {
        Self { x: self.z, y: self.y, z: self.x }
    }

    /// Decompose vector into direction (normalized vector) and magnitude
    pub fn decompose(&self) -> (Self, f64) {
        let mag = self.magnitude();
        if mag < 1e-10 {
            (Self::zero(), 0.0)
        } else {
            (self / mag, mag)
        }
    }

    /// Schlick approximation for reflectance
    pub fn schlick_reflectance(cosine: f64, ref_idx: f64) -> f64 {
        let r0 = ((1.0 - ref_idx) / (1.0 + ref_idx)).powi(2);
        r0 + (1.0 - r0) * (1.0 - cosine).powi(5)
    }

    /// Compute numerical gradient approximation given scalar function f at this vector
    pub fn numerical_gradient<F>(&self, epsilon: f64, f: F) -> Self
    where
        F: Fn(Vector3) -> f64,
    {
        let dx = Vector3::new(epsilon, 0.0, 0.0);
        let dy = Vector3::new(0.0, epsilon, 0.0);
        let dz = Vector3::new(0.0, 0.0, epsilon);

        let df_dx = (f(*self + dx) - f(*self - dx)) / (2.0 * epsilon);
        let df_dy = (f(*self + dy) - f(*self - dy)) / (2.0 * epsilon);
        let df_dz = (f(*self + dz) - f(*self - dz)) / (2.0 * epsilon);

        Vector3::new(df_dx, df_dy, df_dz)
    }

    /// Generate point on a helix given axis, radius, pitch, and angle
    pub fn helix_point(axis: &Vector3, radius: f64, pitch: f64, angle: f64) -> Self {
        let orthogonal_basis = Self::orthogonal_basis(axis);
        orthogonal_basis[0].scale(radius * angle.cos()) +
        orthogonal_basis[1].scale(radius * angle.sin()) +
        orthogonal_basis[2].scale(pitch * angle / (2.0 * std::f64::consts::PI))
    }
}

//------------------------------------------------------------------------------
// Interpolation Methods
//------------------------------------------------------------------------------

impl Vector3 {
    /// Calculate the lerp (linear interpolation) between this vector and another
    pub fn lerp(&self, other: &Vector3, t: f64) -> Self {
        Self {
            x: self.x + (other.x - self.x) * t,
            y: self.y + (other.y - self.y) * t,
            z: self.z + (other.z - self.z) * t,
        }
    }
    
    /// Linear interpolation with clamping between 0 and 1
    pub fn lerp_clamped(&self, other: &Vector3, t: f64) -> Self {
        self.lerp(other, t.clamp(0.0, 1.0))
    }
    
    /// Spherical linear interpolation (slerp) between two vectors
    pub fn slerp(&self, other: &Vector3, t: f64) -> Self {
        let dot = self.dot(other).clamp(-1.0, 1.0);
        let theta = dot.acos();
        
        if theta.abs() < 1e-10 {
            return self.lerp(other, t);
        }
        
        let sin_theta = theta.sin();
        let scale1 = ((1.0 - t) * theta).sin() / sin_theta;
        let scale2 = (t * theta).sin() / sin_theta;
        
        Self {
            x: scale1 * self.x + scale2 * other.x,
            y: scale1 * self.y + scale2 * other.y,
            z: scale1 * self.z + scale2 * other.z,
        }
    }
    
    /// Cubic interpolation between vectors (smoother than linear)
    pub fn cubic_interpolate(&self, other: &Vector3, pre: &Vector3, post: &Vector3, t: f64) -> Self {
        let t2 = t * t;
        let t3 = t2 * t;
        
        let a = 2.0 * t3 - 3.0 * t2 + 1.0;
        let b = -2.0 * t3 + 3.0 * t2;
        let c = t3 - 2.0 * t2 + t;
        let d = t3 - t2;
        
        self.scale(a) + 
            other.scale(b) + 
            (other - pre).scale(c) + 
            (post - other).scale(d)
    }
}

//------------------------------------------------------------------------------
// Geometric Operations
//------------------------------------------------------------------------------

impl Vector3 {
    /// Check if the vector is close to zero in all dimensions
    pub fn is_near_zero(&self, epsilon: f64) -> bool {
        self.x.abs() < epsilon && self.y.abs() < epsilon && self.z.abs() < epsilon
    }
    
    /// Returns the angle between this vector and another vector in radians
    pub fn angle_between(&self, other: &Vector3) -> f64 {
        let dot = self.dot(other);
        let mag_product = self.magnitude() * other.magnitude();
        
        if mag_product < 1e-10 {
            0.0 // Prevent division by near-zero
        } else {
            // Clamp to handle floating point imprecision
            let cosine = (dot / mag_product).clamp(-1.0, 1.0);
            cosine.acos()
        }
    }
    
    /// Project this vector onto another vector
    pub fn project_onto(&self, other: &Vector3) -> Self {
        let other_mag_squared = other.magnitude_squared();
        if other_mag_squared < 1e-10 {
            return Self::zero();
        }
        
        let dot = self.dot(other);
        other.scale(dot / other_mag_squared)
    }
    
    /// Calculate the rejection of this vector from another vector
    /// (Opposite of projection - the component perpendicular to other)
    pub fn reject_from(&self, other: &Vector3) -> Self {
        let projection = self.project_onto(other);
        self - &projection
    }
    
    /// Reflect this vector across a normal vector
    pub fn reflect(&self, normal: &Vector3) -> Self {
        // r = v - 2(v·n)n
        let normal_unit = normal.normalized();
        let dot2 = 2.0 * self.dot(&normal_unit);
        Self {
            x: self.x - dot2 * normal_unit.x,
            y: self.y - dot2 * normal_unit.y,
            z: self.z - dot2 * normal_unit.z,
        }
    }

    /// Reflect vector across a plane defined by a point and normal
    pub fn reflect_plane(&self, point: &Vector3, normal: &Vector3) -> Self {
        let normal = normal.normalized();
        let distance = (self - point).dot(&normal);
        self - &(normal * (2.0 * distance))
    }
    
    /// Project this vector onto a plane defined by its normal
    pub fn project_onto_plane(&self, plane_normal: &Vector3) -> Self {
        let normal = plane_normal.normalized();
        self - &normal.scale(self.dot(&normal))
    }
    
    /// Calculate the distance from this point to a plane defined by a point and normal
    pub fn distance_to_plane(&self, plane_point: &Vector3, plane_normal: &Vector3) -> f64 {
        let normal = plane_normal.normalized();
        (self - plane_point).dot(&normal).abs()
    }
    
    /// Rotate this vector around an arbitrary axis by a given angle in radians
    pub fn rotate_around_axis(&self, axis: &Vector3, angle: f64) -> Self {
        // Ensure axis is normalized
        let axis = axis.normalized();
        
        // Rodrigues rotation formula
        let cos_angle = angle.cos();
        let sin_angle = angle.sin();
        
        // v * cos(θ) + (axis × v) * sin(θ) + axis * (axis · v) * (1 - cos(θ))
        self.scale(cos_angle) +
            axis.cross(self).scale(sin_angle) +
            axis.scale(axis.dot(self) * (1.0 - cos_angle))
    }
    
    /// Get a vector perpendicular to this one (not unique)
    pub fn perpendicular(&self) -> Self {
        if self.x.abs() < self.y.abs() {
            // If x is the smallest component, create a perpendicular vector in the x-direction
            Self::new(0.0, -self.z, self.y).normalized()
        } else {
            // Otherwise, create a perpendicular vector in the y-direction
            Self::new(-self.z, 0.0, self.x).normalized()
        }
    }
    
    /// Calculate the scalar triple product: self · (a × b)
    pub fn scalar_triple_product(&self, a: &Vector3, b: &Vector3) -> f64 {
        self.dot(&a.cross(b))
    }
}

//------------------------------------------------------------------------------
// Component-wise Operations
//------------------------------------------------------------------------------

impl Vector3 {
    /// Component-wise minimum of two vectors
    pub fn component_min(&self, other: &Vector3) -> Self {
        Self {
            x: self.x.min(other.x),
            y: self.y.min(other.y),
            z: self.z.min(other.z),
        }
    }
    
    /// Component-wise maximum of two vectors
    pub fn component_max(&self, other: &Vector3) -> Self {
        Self {
            x: self.x.max(other.x),
            y: self.y.max(other.y),
            z: self.z.max(other.z),
        }
    }
    
    /// Component-wise absolute value
    pub fn abs(&self) -> Self {
        Self {
            x: self.x.abs(),
            y: self.y.abs(),
            z: self.z.abs(),
        }
    }
    
    /// Component-wise multiplication (Hadamard product)
    pub fn component_mul(&self, other: &Vector3) -> Self {
        Self {
            x: self.x * other.x,
            y: self.y * other.y,
            z: self.z * other.z,
        }
    }
    
    /// Component-wise division
    pub fn component_div(&self, other: &Vector3) -> Self {
        if other.x.abs() < 1e-10 || other.y.abs() < 1e-10 || other.z.abs() < 1e-10 {
            panic!("Division by near-zero component");
        }
        Self {
            x: self.x / other.x,
            y: self.y / other.y,
            z: self.z / other.z,
        }
    }
    
    /// Clamp each component between min and max values
    pub fn clamp(&self, min: f64, max: f64) -> Self {
        Self {
            x: self.x.clamp(min, max),
            y: self.y.clamp(min, max),
            z: self.z.clamp(min, max),
        }
    }
    
    /// Check if two vectors are approximately equal within epsilon
    pub fn approx_eq(&self, other: &Vector3, epsilon: f64) -> bool {
        (self.x - other.x).abs() < epsilon &&
        (self.y - other.y).abs() < epsilon &&
        (self.z - other.z).abs() < epsilon
    }
}

//------------------------------------------------------------------------------
// Coordinate System Conversions
//------------------------------------------------------------------------------

impl Vector3 {
    /// Convert to spherical coordinates: (r, theta, phi)
    /// r = magnitude, theta = inclination from +z axis, phi = azimuth from +x axis
    pub fn to_spherical(&self) -> (f64, f64, f64) {
        let r = self.magnitude();
        if r < 1e-10 {
            return (0.0, 0.0, 0.0); // Avoid division by zero
        }
        
        let theta = (self.z / r).acos();
        let phi = self.y.atan2(self.x);
        
        (r, theta, phi)
    }
    
    /// Create a vector from spherical coordinates
    pub fn from_spherical(r: f64, theta: f64, phi: f64) -> Self {
        Self {
            x: r * theta.sin() * phi.cos(),
            y: r * theta.sin() * phi.sin(),
            z: r * theta.cos(),
        }
    }
    
    /// Create a vector from cylindrical coordinates (r, theta, z)
    pub fn from_cylindrical(r: f64, theta: f64, z: f64) -> Self {
        Self {
            x: r * theta.cos(),
            y: r * theta.sin(),
            z,
        }
    }
    
    /// Convert to cylindrical coordinates: (r, theta, z)
    pub fn to_cylindrical(&self) -> (f64, f64, f64) {
        let r = (self.x * self.x + self.y * self.y).sqrt();
        let theta = self.y.atan2(self.x);
        (r, theta, self.z)
    }
}

//------------------------------------------------------------------------------
// Geometric Utility Functions
//------------------------------------------------------------------------------

impl Vector3 {
    /// Compute the refraction vector through a surface with normal and ratio of refraction indices
    pub fn refract(&self, normal: &Vector3, eta_ratio: f64) -> Option<Self> {
        let unit_direction = self.normalized();
        let cos_theta = (-unit_direction).dot(normal).min(1.0);
        let sin_theta_squared = 1.0 - cos_theta * cos_theta;
    
        // Total Internal Reflection condition
        if eta_ratio * eta_ratio * sin_theta_squared > 1.0 {
            return None;
        }
    
        let cos_theta_prime = (1.0 - eta_ratio * eta_ratio * sin_theta_squared).sqrt();
        let r_out_perp = eta_ratio * (unit_direction + normal.scale(cos_theta));
        let r_out_parallel = normal.scale(-cos_theta_prime);
        Some(r_out_perp + r_out_parallel)
    }    
    
    /// Calculate the barycentric coordinates of a point relative to a triangle
    pub fn barycentric_coordinates(&self, a: &Vector3, b: &Vector3, c: &Vector3) -> (f64, f64, f64) {
        let v0 = b - a;
        let v1 = c - a;
        let v2 = self - a;
        
        let d00 = v0.dot(&v0);
        let d01 = v0.dot(&v1);
        let d11 = v1.dot(&v1);
        let d20 = v2.dot(&v0);
        let d21 = v2.dot(&v1);
        
        let denom = d00 * d11 - d01 * d01;
        if denom.abs() < 1e-10 {
            return (0.0, 0.0, 0.0); // Degenerate triangle
        }
        
        let v = (d11 * d20 - d01 * d21) / denom;
        let w = (d00 * d21 - d01 * d20) / denom;
        let u = 1.0 - v - w;
        
        (u, v, w)
    }
    
    /// Check if point is inside triangle defined by three vertices
    pub fn is_inside_triangle(&self, a: &Vector3, b: &Vector3, c: &Vector3) -> bool {
        let (u, v, w) = self.barycentric_coordinates(a, b, c);
        u >= 0.0 && v >= 0.0 && w >= 0.0 && (u + v + w).abs() - 1.0 < 1e-10
    }
    
    /// Calculate the closest point on a line segment to this point
    pub fn closest_point_on_segment(&self, start: &Vector3, end: &Vector3) -> Self {
        let segment = end - start;
        let length_squared = segment.magnitude_squared();
        
        if length_squared < 1e-10 {
            return *start; // Start and end are the same point
        }
        
        // Calculate projection and clamp to segment
        let t = ((self - start).dot(&segment) / length_squared).clamp(0.0, 1.0);
        start + &segment.scale(t)
    }
    
    /// Check if three points are collinear (lie on the same line)
    pub fn are_collinear(a: &Vector3, b: &Vector3, c: &Vector3) -> bool {
        let ab = b - a;
        let ac = c - a;
        ab.cross(&ac).magnitude_squared() < 1e-10
    }
}

//------------------------------------------------------------------------------
// Static Methods for Collections of Vectors
//------------------------------------------------------------------------------

impl Vector3 {
    /// Calculate the mean of a collection of vectors
    pub fn mean(vectors: &[Vector3]) -> Option<Vector3> {
        if vectors.is_empty() {
            return None;
        }
        
        let sum = vectors.iter().fold(Vector3::zero(), |acc, v| acc + *v);
        Some(sum / vectors.len() as f64)
    }
    
    /// Compute the centroid of a collection of points
    pub fn centroid(points: &[Vector3]) -> Option<Vector3> {
        Self::mean(points)
    }
    
    /// Create an orthogonal basis from a single direction vector
    pub fn orthogonal_basis(direction: &Vector3) -> [Vector3; 3] {
        let z = direction.normalized();
        let x = z.perpendicular();
        let y = z.cross(&x);
        
        [x, y, z]
    }

    /// Calculate variance of a collection of vectors
    pub fn variance(vectors: &[Vector3], mean: Option<Vector3>) -> Option<Vector3> {
        if vectors.is_empty() {
            return None;
        }
        
        let mean_vec = match mean {
            Some(m) => m,
            None => Vector3::mean(vectors)?,
        };
        
        let variance = vectors.iter().fold(Vector3::zero(), |acc, v| {
            let diff = v - &mean_vec;
            acc + Vector3::new(diff.x * diff.x, diff.y * diff.y, diff.z * diff.z)
        });
        
        Some(variance / vectors.len() as f64)
    }
    
    /// Find the vector with minimum magnitude in a collection
    pub fn min_magnitude(vectors: &[Vector3]) -> Option<&Vector3> {
        vectors.iter().min_by(|a, b| 
            a.magnitude_squared().partial_cmp(&b.magnitude_squared()).unwrap_or(std::cmp::Ordering::Equal)
        )
    }
    
    /// Find the vector with maximum magnitude in a collection
    pub fn max_magnitude(vectors: &[Vector3]) -> Option<&Vector3> {
        vectors.iter().max_by(|a, b| 
            a.magnitude_squared().partial_cmp(&b.magnitude_squared()).unwrap_or(std::cmp::Ordering::Equal)
        )
    }
    
    /// Compute bounding box (min and max corners) for a collection of points
    pub fn bounding_box(points: &[Vector3]) -> Option<(Vector3, Vector3)> {
        if points.is_empty() {
            return None;
        }
        
        let mut min = points[0];
        let mut max = points[0];
        
        for point in points.iter().skip(1) {
            min = min.component_min(point);
            max = max.component_max(point);
        }
        
        Some((min, max))
    }
    
    /// Compute the centroid of a triangle
    pub fn triangle_centroid(a: &Vector3, b: &Vector3, c: &Vector3) -> Self {
        (a + b + *c) / 3.0
    }
    
    /// Calculate the area of a triangle
    pub fn triangle_area(a: &Vector3, b: &Vector3, c: &Vector3) -> f64 {
        let ab = b - a;
        let ac = c - a;
        ab.cross(&ac).magnitude() * 0.5
    }
    
    /// Calculate the volume of a tetrahedron
    pub fn tetrahedron_volume(a: &Vector3, b: &Vector3, c: &Vector3, d: &Vector3) -> f64 {
        let ab = b - a;
        let ac = c - a;
        let ad = d - a;
        ab.scalar_triple_product(&ac, &ad).abs() / 6.0
    }
}

//------------------------------------------------------------------------------
// Operator Implementations
//------------------------------------------------------------------------------

// Addition: Vector3 + Vector3
impl std::ops::Add for Vector3 {
    type Output = Vector3;
    
    fn add(self, other: Vector3) -> Vector3 {
        Vector3 {
            x: self.x + other.x,
            y: self.y + other.y,
            z: self.z + other.z,
        }
    }
}

// Addition with reference: &Vector3 + &Vector3
impl std::ops::Add for &Vector3 {
    type Output = Vector3;
    
    fn add(self, other: &Vector3) -> Vector3 {
        Vector3 {
            x: self.x + other.x,
            y: self.y + other.y,
            z: self.z + other.z,
        }
    }
}

// Subtraction: Vector3 - Vector3
impl std::ops::Sub for Vector3 {
    type Output = Vector3;
    
    fn sub(self, other: Vector3) -> Vector3 {
        Vector3 {
            x: self.x - other.x,
            y: self.y - other.y,
            z: self.z - other.z,
        }
    }
}

// Subtraction with reference: &Vector3 - &Vector3
impl std::ops::Sub for &Vector3 {
    type Output = Vector3;
    
    fn sub(self, other: &Vector3) -> Vector3 {
        Vector3 {
            x: self.x - other.x,
            y: self.y - other.y,
            z: self.z - other.z,
        }
    }
}

// Multiplication by scalar: Vector3 * f64
impl std::ops::Mul<f64> for Vector3 {
    type Output = Vector3;
    
    fn mul(self, scalar: f64) -> Vector3 {
        Vector3 {
            x: self.x * scalar,
            y: self.y * scalar,
            z: self.z * scalar,
        }
    }
}

// Multiplication by scalar with reference: &Vector3 * f64
impl std::ops::Mul<f64> for &Vector3 {
    type Output = Vector3;
    
    fn mul(self, scalar: f64) -> Vector3 {
        Vector3 {
            x: self.x * scalar,
            y: self.y * scalar,
            z: self.z * scalar,
        }
    }
}

// Multiplication (reversed): f64 * Vector3
impl std::ops::Mul<Vector3> for f64 {
    type Output = Vector3;
    
    fn mul(self, vec: Vector3) -> Vector3 {
        Vector3 {
            x: vec.x * self,
            y: vec.y * self,
            z: vec.z * self,
        }
    }
}

// Multiplication (reversed) with reference: f64 * &Vector3
impl std::ops::Mul<&Vector3> for f64 {
    type Output = Vector3;
    
    fn mul(self, vec: &Vector3) -> Vector3 {
        Vector3 {
            x: vec.x * self,
            y: vec.y * self,
            z: vec.z * self,
        }
    }
}

// Division by scalar: Vector3 / f64
impl std::ops::Div<f64> for Vector3 {
    type Output = Vector3;
    
    fn div(self, scalar: f64) -> Vector3 {
        if scalar.abs() < 1e-10 {
            panic!("Division by near-zero value");
        }
        Vector3 {
            x: self.x / scalar,
            y: self.y / scalar,
            z: self.z / scalar,
        }
    }
}

// Division by scalar with reference: &Vector3 / f64
impl std::ops::Div<f64> for &Vector3 {
    type Output = Vector3;
    
    fn div(self, scalar: f64) -> Vector3 {
        if scalar.abs() < 1e-10 {
            panic!("Division by near-zero value");
        }
        Vector3 {
            x: self.x / scalar,
            y: self.y / scalar,
            z: self.z / scalar,
        }
    }
}

// Negation: -Vector3
impl std::ops::Neg for Vector3 {
    type Output = Vector3;
    
    fn neg(self) -> Vector3 {
        Vector3 {
            x: -self.x,
            y: -self.y,
            z: -self.z,
        }
    }
}

// Negation with reference: -&Vector3
impl std::ops::Neg for &Vector3 {
    type Output = Vector3;
    
    fn neg(self) -> Vector3 {
        Vector3 {
            x: -self.x,
            y: -self.y,
            z: -self.z,
        }
    }
}

// Addition assignment: Vector3 += Vector3
impl std::ops::AddAssign for Vector3 {
    fn add_assign(&mut self, other: Vector3) {
        self.x += other.x;
        self.y += other.y;
        self.z += other.z;
    }
}

// Subtraction assignment: Vector3 -= Vector3
impl std::ops::SubAssign for Vector3 {
    fn sub_assign(&mut self, other: Vector3) {
        self.x -= other.x;
        self.y -= other.y;
        self.z -= other.z;
    }
}

// Multiplication assignment: Vector3 *= f64
impl std::ops::MulAssign<f64> for Vector3 {
    fn mul_assign(&mut self, scalar: f64) {
        self.x *= scalar;
        self.y *= scalar;
        self.z *= scalar;
    }
}

// Division assignment: Vector3 /= f64
impl std::ops::DivAssign<f64> for Vector3 {
    fn div_assign(&mut self, scalar: f64) {
        if scalar.abs() < 1e-10 {
            panic!("Division by near-zero value");
        }
        self.x /= scalar;
        self.y /= scalar;
        self.z /= scalar;
    }
}

//------------------------------------------------------------------------------
// Unit Tests
//------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::f64::EPSILON;
    
    // Helper function to check if two f64 values are approximately equal
    fn approx_eq(a: f64, b: f64, epsilon: f64) -> bool {
        (a - b).abs() < epsilon
    }
    
    // Helper function to check if two Vector3 instances are approximately equal
    fn vec_approx_eq(a: &Vector3, b: &Vector3, epsilon: f64) -> bool {
        approx_eq(a.x, b.x, epsilon) && 
        approx_eq(a.y, b.y, epsilon) && 
        approx_eq(a.z, b.z, epsilon)
    }
    
    // Basic construction and access tests
    #[test]
    fn test_construction() {
        let v = Vector3::new(1.0, 2.0, 3.0);
        assert_eq!(v.x, 1.0);
        assert_eq!(v.y, 2.0);
        assert_eq!(v.z, 3.0);
        
        let zero = Vector3::zero();
        assert_eq!(zero.x, 0.0);
        assert_eq!(zero.y, 0.0);
        assert_eq!(zero.z, 0.0);
        
        let ux = Vector3::unit_x();
        assert_eq!(ux, Vector3::new(1.0, 0.0, 0.0));
        
        let uy = Vector3::unit_y();
        assert_eq!(uy, Vector3::new(0.0, 1.0, 0.0));
        
        let uz = Vector3::unit_z();
        assert_eq!(uz, Vector3::new(0.0, 0.0, 1.0));
    }
    
    // Vector properties tests
    #[test]
    fn test_magnitude() {
        let v = Vector3::new(3.0, 4.0, 5.0);
        let expected = (3.0_f64.powi(2) + 4.0_f64.powi(2) + 5.0_f64.powi(2)).sqrt();
        assert!(approx_eq(v.magnitude(), expected, EPSILON));
        
        // Test zero vector
        let zero = Vector3::zero();
        assert_eq!(zero.magnitude(), 0.0);
    }
    
    #[test]
    fn test_magnitude_squared() {
        let v = Vector3::new(3.0, 4.0, 5.0);
        let expected = 3.0_f64.powi(2) + 4.0_f64.powi(2) + 5.0_f64.powi(2);
        assert!(approx_eq(v.magnitude_squared(), expected, EPSILON));
        
        // Special case - common right triangle
        let v = Vector3::new(3.0, 4.0, 0.0);
        assert_eq!(v.magnitude_squared(), 25.0);
        
        // Zero vector
        let zero = Vector3::zero();
        assert_eq!(zero.magnitude_squared(), 0.0);
    }
    
    #[test]
    fn test_distance() {
        let v1 = Vector3::new(1.0, 2.0, 3.0);
        let v2 = Vector3::new(4.0, 6.0, 8.0);
        let expected = ((3.0_f64).powi(2) + (4.0_f64).powi(2) + (5.0_f64).powi(2)).sqrt();
        assert!(approx_eq(v1.distance(&v2), expected, EPSILON));
        
        // Same point distance should be zero
        let v3 = Vector3::new(1.0, 2.0, 3.0);
        assert_eq!(v1.distance(&v3), 0.0);
        
        // Common case - 3-4-5 triangle
        let origin = Vector3::zero();
        let v4 = Vector3::new(3.0, 4.0, 0.0);
        assert_eq!(origin.distance(&v4), 5.0);
    }
    
    #[test]
    fn test_normalized() {
        let v = Vector3::new(3.0, 4.0, 5.0);
        let magnitude = (3.0_f64.powi(2) + 4.0_f64.powi(2) + 5.0_f64.powi(2)).sqrt();
        let expected = Vector3::new(3.0 / magnitude, 4.0 / magnitude, 5.0 / magnitude);
        let normalized = v.normalized();
        
        assert!(vec_approx_eq(&normalized, &expected, EPSILON));
        assert!(approx_eq(normalized.magnitude(), 1.0, EPSILON));
        
        // Unit vector should remain unchanged
        let ux = Vector3::unit_x();
        assert_eq!(ux.normalized(), ux);
        
        // Zero vector should remain zero
        let zero = Vector3::zero();
        assert_eq!(zero.normalized(), zero);
    }
    
    #[test]
    fn test_unit_vectors() {
        let ux = Vector3::unit_x();
        let uy = Vector3::unit_y();
        let uz = Vector3::unit_z();
        
        // Verify magnitudes
        assert_eq!(ux.magnitude(), 1.0);
        assert_eq!(uy.magnitude(), 1.0);
        assert_eq!(uz.magnitude(), 1.0);
        
        // Test orthogonality (perpendicular)
        assert_eq!(ux.dot(&uy), 0.0);
        assert_eq!(ux.dot(&uz), 0.0);
        assert_eq!(uy.dot(&uz), 0.0);
        
        // Test cross products
        assert_eq!(ux.cross(&uy), uz);
        assert_eq!(uy.cross(&uz), ux);
        assert_eq!(uz.cross(&ux), uy);
        
        // Negative cross products
        assert_eq!(uy.cross(&ux), -uz);
        assert_eq!(uz.cross(&uy), -ux);
        assert_eq!(ux.cross(&uz), -uy);
    }
    
    // Vector operations tests
    #[test]
    fn test_dot_product() {
        let v1 = Vector3::new(1.0, 2.0, 3.0);
        let v2 = Vector3::new(4.0, 5.0, 6.0);
        let expected = 1.0 * 4.0 + 2.0 * 5.0 + 3.0 * 6.0;
        assert!(approx_eq(v1.dot(&v2), expected, EPSILON));
        
        // Perpendicular vectors should have dot product of zero
        let ux = Vector3::unit_x();
        let uy = Vector3::unit_y();
        assert_eq!(ux.dot(&uy), 0.0);
        
        // Parallel vectors with dot product equal to magnitude product
        let v3 = Vector3::new(2.0, 0.0, 0.0);
        assert_eq!(ux.dot(&v3), 2.0);
        
        // Anti-parallel vectors
        let v4 = Vector3::new(-1.0, 0.0, 0.0);
        assert_eq!(ux.dot(&v4), -1.0);
    }
    
    #[test]
    fn test_cross_product() {
        let v1 = Vector3::new(1.0, 2.0, 3.0);
        let v2 = Vector3::new(4.0, 5.0, 6.0);
        let expected = Vector3::new(
            2.0 * 6.0 - 3.0 * 5.0,
            3.0 * 4.0 - 1.0 * 6.0,
            1.0 * 5.0 - 2.0 * 4.0
        );
        assert_eq!(v1.cross(&v2), expected);
        
        // Parallel vectors should have zero cross product
        let v3 = Vector3::new(2.0, 4.0, 6.0);
        assert_eq!(v1.cross(&v3), Vector3::zero());
        
        // Standard basis
        let ux = Vector3::unit_x();
        let uy = Vector3::unit_y();
        let uz = Vector3::unit_z();
        assert_eq!(ux.cross(&uy), uz);
    }
    
    #[test]
    fn test_scale() {
        let v = Vector3::new(1.0, 2.0, 3.0);
        let scalar = 2.5;
        let expected = Vector3::new(1.0 * scalar, 2.0 * scalar, 3.0 * scalar);
        assert_eq!(v.scale(scalar), expected);
        
        // Scale by zero
        assert_eq!(v.scale(0.0), Vector3::zero());
        
        // Scale by negative
        assert_eq!(v.scale(-1.0), -v);
    }
    
    #[test]
    fn test_negate() {
        let v = Vector3::new(1.0, 2.0, 3.0);
        let expected = Vector3::new(-1.0, -2.0, -3.0);
        assert_eq!(v.negate(), expected);
        
        // Double negation
        assert_eq!(v.negate().negate(), v);
        
        // Zero negation
        let zero = Vector3::zero();
        assert_eq!(zero.negate(), zero);
    }
    
    #[test]
    fn test_lerp() {
        let v1 = Vector3::new(1.0, 2.0, 3.0);
        let v2 = Vector3::new(5.0, 6.0, 7.0);
        
        // t = 0 should give first vector
        assert_eq!(v1.lerp(&v2, 0.0), v1);
        
        // t = 1 should give second vector
        assert_eq!(v1.lerp(&v2, 1.0), v2);
        
        // t = 0.5 should give the midpoint
        let midpoint = Vector3::new(3.0, 4.0, 5.0);
        assert_eq!(v1.lerp(&v2, 0.5), midpoint);
        
        // t = 0.25
        let quarter = Vector3::new(2.0, 3.0, 4.0);
        assert_eq!(v1.lerp(&v2, 0.25), quarter);
        
        // t > 1 - extrapolation
        let beyond = Vector3::new(9.0, 10.0, 11.0);
        assert_eq!(v1.lerp(&v2, 2.0), beyond);
        
        // t < 0 - extrapolation
        let before = Vector3::new(-3.0, -2.0, -1.0);
        assert_eq!(v1.lerp(&v2, -1.0), before);
    }
    
    #[test]
    fn test_is_near_zero() {
        let v1 = Vector3::new(0.001, 0.0005, 0.0009);
        assert!(v1.is_near_zero(0.01));
        assert!(!v1.is_near_zero(0.0001));
        
        let v2 = Vector3::new(0.0, 0.0, 0.0);
        assert!(v2.is_near_zero(0.0000001));
        
        let v3 = Vector3::new(0.1, 0.0, 0.0);
        assert!(!v3.is_near_zero(0.01));
    }
    
    #[test]
    fn test_angle_between() {
        let ux = Vector3::unit_x();
        let uy = Vector3::unit_y();
        
        // 90 degrees = π/2
        assert!(approx_eq(ux.angle_between(&uy), std::f64::consts::FRAC_PI_2, EPSILON));
        
        // 0 degrees
        assert!(approx_eq(ux.angle_between(&ux), 0.0, EPSILON));
        
        // 180 degrees = π
        let neg_x = -ux;
        assert!(approx_eq(ux.angle_between(&neg_x), std::f64::consts::PI, EPSILON));
        
        // 45 degrees = π/4
        let v45 = Vector3::new(1.0, 1.0, 0.0).normalized();
        assert!(approx_eq(ux.angle_between(&v45), std::f64::consts::FRAC_PI_4, EPSILON));
        
        // Zero vector edge case
        let zero = Vector3::zero();
        assert_eq!(zero.angle_between(&ux), 0.0);
        assert_eq!(ux.angle_between(&zero), 0.0);
    }
    
    #[test]
    fn test_project_onto() {
        let v = Vector3::new(3.0, 4.0, 0.0);
        let ux = Vector3::unit_x();
        
        // Project onto x-axis
        let projection = v.project_onto(&ux);
        assert_eq!(projection, Vector3::new(3.0, 0.0, 0.0));
        
        // Project onto zero vector
        let zero = Vector3::zero();
        assert_eq!(v.project_onto(&zero), zero);
        
        // Project onto self
        assert_eq!(v.project_onto(&v), v);
        
        // Project onto perpendicular
        let uy = Vector3::unit_y();
        let v2 = Vector3::new(5.0, 0.0, 0.0);
        assert_eq!(v2.project_onto(&uy), zero);
        
        // Project parallel vector
        let v3 = Vector3::new(2.0, 0.0, 0.0);
        let v4 = Vector3::new(3.0, 0.0, 0.0);
        assert_eq!(v3.project_onto(&v4), v3);
    }
    
    #[test]
    fn test_reflect() {
        // Reflect vector (1,1,0) across x-axis (normal is y-axis)
        let v = Vector3::new(1.0, 1.0, 0.0);
        let normal = Vector3::unit_y();
        let reflection = v.reflect(&normal);
        assert!(vec_approx_eq(&reflection, &Vector3::new(1.0, -1.0, 0.0), EPSILON));
        
        // Reflect along surface (normal perpendicular to vector)
        let v2 = Vector3::unit_x();
        let reflection2 = v2.reflect(&Vector3::unit_y());
        assert!(vec_approx_eq(&reflection2, &v2, EPSILON));
        
        // Reflect 45-degree vector off horizontal surface
        let v3 = Vector3::new(1.0, -1.0, 0.0).normalized();
        let reflection3 = v3.reflect(&Vector3::unit_y());
        assert!(vec_approx_eq(&reflection3, &Vector3::new(1.0, 1.0, 0.0).normalized(), EPSILON));
        
        // Normal is automatically normalized
        let v4 = Vector3::new(0.0, 1.0, 0.0);
        let normal4 = Vector3::new(0.0, 2.0, 0.0); // Non-unit normal
        let reflection4 = v4.reflect(&normal4);
        assert!(vec_approx_eq(&reflection4, &Vector3::new(0.0, -1.0, 0.0), EPSILON));
    }
    
    // Operator tests
    #[test]
    fn test_operators() {
        // Addition
        let v1 = Vector3::new(1.0, 2.0, 3.0);
        let v2 = Vector3::new(4.0, 5.0, 6.0);
        let sum = v1 + v2;
        assert_eq!(sum, Vector3::new(5.0, 7.0, 9.0));
        
        // Addition with references
        let sum_ref = &v1 + &v2;
        assert_eq!(sum_ref, Vector3::new(5.0, 7.0, 9.0));
        
        // Subtraction
        let diff = v2 - v1;
        assert_eq!(diff, Vector3::new(3.0, 3.0, 3.0));
        
        // Subtraction with references
        let diff_ref = &v2 - &v1;
        assert_eq!(diff_ref, Vector3::new(3.0, 3.0, 3.0));
        
        // Scalar multiplication
        let scaled = v1 * 2.0;
        assert_eq!(scaled, Vector3::new(2.0, 4.0, 6.0));
        
        // Scalar multiplication with reference
        let scaled_ref = &v1 * 2.0;
        assert_eq!(scaled_ref, Vector3::new(2.0, 4.0, 6.0));
        
        // Reversed scalar multiplication
        let scaled_rev = 2.0 * v1;
        assert_eq!(scaled_rev, Vector3::new(2.0, 4.0, 6.0));
        
        // Reversed scalar multiplication with reference
        let scaled_rev_ref = 2.0 * &v1;
        assert_eq!(scaled_rev_ref, Vector3::new(2.0, 4.0, 6.0));
        
        // Division by scalar
        let divided = v1 / 2.0;
        assert_eq!(divided, Vector3::new(0.5, 1.0, 1.5));
        
        // Division by scalar with reference
        let divided_ref = &v1 / 2.0;
        assert_eq!(divided_ref, Vector3::new(0.5, 1.0, 1.5));
        
        // Negation
        let neg = -v1;
        assert_eq!(neg, Vector3::new(-1.0, -2.0, -3.0));
        
        // Negation with reference
        let neg_ref = -&v1;
        assert_eq!(neg_ref, Vector3::new(-1.0, -2.0, -3.0));
    }
    
    #[test]
    fn test_compound_assignments() {
        // Addition assignment
        let mut v1 = Vector3::new(1.0, 2.0, 3.0);
        let v2 = Vector3::new(4.0, 5.0, 6.0);
        v1 += v2;
        assert_eq!(v1, Vector3::new(5.0, 7.0, 9.0));
        
        // Subtraction assignment
        let mut v3 = Vector3::new(5.0, 7.0, 9.0);
        let v4 = Vector3::new(1.0, 2.0, 3.0);
        v3 -= v4;
        assert_eq!(v3, Vector3::new(4.0, 5.0, 6.0));
        
        // Multiplication assignment
        let mut v5 = Vector3::new(1.0, 2.0, 3.0);
        v5 *= 2.0;
        assert_eq!(v5, Vector3::new(2.0, 4.0, 6.0));
        
        // Division assignment
        let mut v6 = Vector3::new(2.0, 4.0, 6.0);
        v6 /= 2.0;
        assert_eq!(v6, Vector3::new(1.0, 2.0, 3.0));
    }
    
    #[test]
    #[should_panic(expected = "Division by near-zero value")]
    fn test_division_by_zero() {
        let v = Vector3::new(1.0, 2.0, 3.0);
        let _ = v / 0.0;
    }
    
    #[test]
    #[should_panic(expected = "Division by near-zero value")]
    fn test_div_assign_by_zero() {
        let mut v = Vector3::new(1.0, 2.0, 3.0);
        v /= 0.0;
    }
    
    // Complex operation chains
    #[test]
    fn test_operation_chains() {
        let v1 = Vector3::unit_x();
        let v2 = Vector3::unit_y();
        
        // Create a vector at 45 degrees between x and y axes
        let v3 = v1.scale(0.5).scale(2.0) + v2.scale(0.5).scale(2.0);
        assert!(vec_approx_eq(&v3, &Vector3::new(1.0, 1.0, 0.0), EPSILON));
        
        // Normalize it to get a unit vector
        let v4 = v3.normalized();
        assert!(approx_eq(v4.magnitude(), 1.0, EPSILON));
        
        // The components should be approximately sqrt(2)/2
        let expected = 1.0 / (2.0_f64).sqrt();
        assert!(approx_eq(v4.x, expected, EPSILON));
        assert!(approx_eq(v4.y, expected, EPSILON));
        
        // Test a more complex chain with multiple operations
        let v5 = (v1 + v2) * 2.0 - v1;
        assert_eq!(v5, Vector3::new(1.0, 2.0, 0.0));
    }
    
    // Edge cases
    #[test]
    fn test_edge_cases() {
        // Very large values
        let large = Vector3::new(1e30, 2e30, 3e30);
        assert!(large.magnitude() > 0.0);
        
        // Very small values
        let small = Vector3::new(1e-30, 2e-30, 3e-30);
        assert!(small.magnitude() > 0.0);
        
        // Mixed large and small
        let mixed = Vector3::new(1e30, 2e-30, 0.0);
        assert!(mixed.magnitude() > 0.0);
        
        // Normalized very small vector should be handled correctly
        let tiny = Vector3::new(1e-100, 1e-100, 1e-100);
        assert_eq!(tiny.normalized(), tiny);
    }
    
    #[test]
    fn test_orthogonalize() {
        let v = Vector3::new(3.0, 4.0, 5.0);
        let base = Vector3::unit_x();
        
        let result = v.orthogonalize(&base);
        
        // Result should be perpendicular to base
        assert!(approx_eq(result.dot(&base), 0.0, EPSILON));
        
        // Original - projection = orthogonalized
        let projection = v.project_onto(&base);
        let expected = v - projection;
        assert!(vec_approx_eq(&result, &expected, EPSILON));
    }
    
    #[test]
    fn test_orthonormal_basis() {
        let v1 = Vector3::new(1.0, 0.0, 0.0);
        let v2 = Vector3::new(0.0, 1.0, 0.0);
        
        let basis = Vector3::orthonormal_basis(&v1, &v2);
        
        // Check orthogonality
        assert!(approx_eq(basis[0].dot(&basis[1]), 0.0, EPSILON));
        assert!(approx_eq(basis[1].dot(&basis[2]), 0.0, EPSILON));
        assert!(approx_eq(basis[2].dot(&basis[0]), 0.0, EPSILON));
        
        // Check unit length
        for i in 0..3 {
            assert!(approx_eq(basis[i].magnitude(), 1.0, EPSILON));
        }
        
        // Check third vector is cross product of first two
        let expected_third = basis[0].cross(&basis[1]);
        assert!(vec_approx_eq(&basis[2], &expected_third, EPSILON));
    }
    
    #[test]
    fn test_determinant() {
        let v1 = Vector3::unit_x();
        let v2 = Vector3::unit_y();
        let v3 = Vector3::unit_z();
        
        // Standard basis determinant should be 1
        assert_eq!(Vector3::determinant(&v1, &v2, &v3), 1.0);
        
        // Switch two vectors, determinant should be -1
        assert_eq!(Vector3::determinant(&v1, &v3, &v2), -1.0);
        
        // Linear dependent vectors, determinant should be 0
        let v4 = Vector3::new(2.0, 0.0, 0.0);
        assert_eq!(Vector3::determinant(&v1, &v4, &v3), 0.0);
    }
    
    #[test]
    fn test_transform_matrices() {
        let v = Vector3::new(1.0, 2.0, 3.0);
        
        // Identity transformations
        let identity3 = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let identity4 = [
            [1.0, 0.0, 0.0, 0.0],
            [0.0, 1.0, 0.0, 0.0],
            [0.0, 0.0, 1.0, 0.0],
            [0.0, 0.0, 0.0, 1.0]
        ];
        
        assert_eq!(v.transform_matrix3(identity3), v);
        assert_eq!(v.transform_matrix4(identity4), v);
        
        // Scale transformations
        let scale3 = [[2.0, 0.0, 0.0], [0.0, 2.0, 0.0], [0.0, 0.0, 2.0]];
        let expected_scale = Vector3::new(2.0, 4.0, 6.0);
        assert_eq!(v.transform_matrix3(scale3), expected_scale);
        
        // Translation (4x4 only)
        let translate4 = [
            [1.0, 0.0, 0.0, 10.0],
            [0.0, 1.0, 0.0, 20.0],
            [0.0, 0.0, 1.0, 30.0],
            [0.0, 0.0, 0.0, 1.0]
        ];
        
        let expected_translate = Vector3::new(11.0, 22.0, 33.0);
        assert_eq!(v.transform_matrix4(translate4), expected_translate);
    }
    
    #[test]
    fn test_robust_perpendicular() {
        let v = Vector3::new(3.0, 4.0, 5.0);
        let perp = v.robust_perpendicular();
        
        // Should be perpendicular to v
        assert!(approx_eq(perp.dot(&v), 0.0, EPSILON));
        
        // Should be unit length
        assert!(approx_eq(perp.magnitude(), 1.0, EPSILON));
    }
    
    #[test]
    fn test_coordinate_swapping() {
        let v = Vector3::new(1.0, 2.0, 3.0);
        
        assert_eq!(v.yxz(), Vector3::new(2.0, 1.0, 3.0));
        assert_eq!(v.zyx(), Vector3::new(3.0, 2.0, 1.0));
    }
    
    #[test]
    fn test_decompose() {
        let v = Vector3::new(3.0, 4.0, 0.0);
        let (dir, mag) = v.decompose();
        
        assert_eq!(mag, 5.0);
        assert!(vec_approx_eq(&dir, &Vector3::new(0.6, 0.8, 0.0), EPSILON));
        
        // Test with zero vector
        let zero = Vector3::zero();
        let (dir_zero, mag_zero) = zero.decompose();
        
        assert_eq!(mag_zero, 0.0);
        assert_eq!(dir_zero, zero);
    }
    
    #[test]
    fn test_schlick_reflectance() {
        // Test at normal incidence (cosine = 1.0)
        let cosine1 = 1.0;
        let ref_idx = 1.5f64;  // Glass-like material
        
        let r0 = ((1.0 - ref_idx) / (1.0 + ref_idx)).powi(2);
        assert!(approx_eq(Vector3::schlick_reflectance(cosine1, ref_idx), r0, EPSILON));
        
        // Test at grazing angle (cosine = 0.0)
        let cosine2 = 0.0;
        assert!(approx_eq(Vector3::schlick_reflectance(cosine2, ref_idx), 1.0, EPSILON));
    }
    
    #[test]
    fn test_numerical_gradient() {
        // f(x,y,z) = x^2 + y^2 + z^2
        let f = |v: Vector3| v.x.powi(2) + v.y.powi(2) + v.z.powi(2);
        
        // Gradient at (1,2,3) is (2,4,6)
        let point = Vector3::new(1.0, 2.0, 3.0);
        let epsilon = 1e-6;
        
        let gradient = point.numerical_gradient(epsilon, f);
        let expected = Vector3::new(2.0, 4.0, 6.0);
        
        assert!(vec_approx_eq(&gradient, &expected, 1e-5));
    }
    
    #[test]
    fn test_interpolation_methods() {
        let v1 = Vector3::new(1.0, 0.0, 0.0);
        let v2 = Vector3::new(0.0, 1.0, 0.0);
        
        // Test lerp_clamped
        assert_eq!(v1.lerp_clamped(&v2, -0.5), v1);
        assert_eq!(v1.lerp_clamped(&v2, 1.5), v2);
        assert_eq!(v1.lerp_clamped(&v2, 0.5), v1.lerp(&v2, 0.5));
        
        // Test slerp
        let mid_slerp = v1.slerp(&v2, 0.5);
        assert!(approx_eq(mid_slerp.magnitude(), 1.0, EPSILON));
        assert!(approx_eq(mid_slerp.dot(&v1), mid_slerp.dot(&v2), EPSILON));
        
        // Test cubic_interpolate
        let pre = Vector3::new(-1.0, 0.0, 0.0);
        let post = Vector3::new(0.0, 2.0, 0.0);
        
        let cubic = v1.cubic_interpolate(&v2, &pre, &post, 0.5);
        assert!(cubic.magnitude() > 0.0);
        // Check endpoints match
        assert_eq!(v1.cubic_interpolate(&v2, &pre, &post, 0.0), v1);
        assert_eq!(v1.cubic_interpolate(&v2, &pre, &post, 1.0), v2);
    }
    
    #[test]
    fn test_component_operations() {
        let v1 = Vector3::new(1.0, -2.0, 3.0);
        let v2 = Vector3::new(-3.0, 4.0, 5.0);
        
        // Test component_min/max
        assert_eq!(v1.component_min(&v2), Vector3::new(-3.0, -2.0, 3.0));
        assert_eq!(v1.component_max(&v2), Vector3::new(1.0, 4.0, 5.0));
        
        // Test abs
        assert_eq!(v1.abs(), Vector3::new(1.0, 2.0, 3.0));
        
        // Test component_mul
        assert_eq!(v1.component_mul(&v2), Vector3::new(-3.0, -8.0, 15.0));
        
        // Test component_div
        let v3 = Vector3::new(6.0, 8.0, 10.0);
        let v4 = Vector3::new(2.0, 4.0, 5.0);
        assert_eq!(v3.component_div(&v4), Vector3::new(3.0, 2.0, 2.0));
        
        // Test clamp
        let v5 = Vector3::new(-2.0, 3.0, 7.0);
        assert_eq!(v5.clamp(0.0, 5.0), Vector3::new(0.0, 3.0, 5.0));
        
        // Test approx_eq
        let v6 = Vector3::new(1.0, 2.0, 3.0);
        let v7 = Vector3::new(1.0 + 1e-6, 2.0 - 1e-6, 3.0 + 1e-6);
        assert!(v6.approx_eq(&v7, 1e-5));
        assert!(!v6.approx_eq(&v7, 1e-7));
    }
    
    #[test]
    #[should_panic(expected = "Division by near-zero component")]
    fn test_component_div_by_zero() {
        let v1 = Vector3::new(1.0, 2.0, 3.0);
        let v2 = Vector3::new(0.0, 1.0, 1.0);
        let _ = v1.component_div(&v2);
    }
    
    #[test]
    fn test_coordinate_conversions() {
        // Test cartesian to spherical and back
        let v1 = Vector3::new(1.0, 1.0, 1.0);
        let (r, theta, phi) = v1.to_spherical();
        let v1_back = Vector3::from_spherical(r, theta, phi);
        assert!(vec_approx_eq(&v1_back, &v1, 1e-5));
        
        // Test basic known conversions
        let v_x = Vector3::unit_x();
        let (r_x, theta_x, phi_x) = v_x.to_spherical();
        assert!(approx_eq(r_x, 1.0, EPSILON));
        assert!(approx_eq(theta_x, std::f64::consts::FRAC_PI_2, EPSILON));
        assert!(approx_eq(phi_x, 0.0, EPSILON));
        
        let v_z = Vector3::unit_z();
        let (r_z, theta_z, phi_z) = v_z.to_spherical();
        assert!(approx_eq(r_z, 1.0, EPSILON));
        assert!(approx_eq(theta_z, 0.0, EPSILON));
        // phi is arbitrary for points on z-axis
        
        // Test cartesian to cylindrical and back
        let v2 = Vector3::new(3.0, 4.0, 5.0);
        let (r_cyl, theta_cyl, z_cyl) = v2.to_cylindrical();
        let v2_back = Vector3::from_cylindrical(r_cyl, theta_cyl, z_cyl);
        assert!(vec_approx_eq(&v2_back, &v2, 1e-5));
        
        // Test zero vector edge case
        let zero = Vector3::zero();
        let (r_zero, theta_zero, phi_zero) = zero.to_spherical();
        assert_eq!(r_zero, 0.0);
        assert_eq!(theta_zero, 0.0);
        assert_eq!(phi_zero, 0.0);
    }
    
    #[test]
    fn test_refraction() {
        let epsilon = 1e-10;

        // Incident vector directly downward (perpendicular incidence)
        let incident = Vector3::new(0.0, -1.0, 0.0);
        let normal = Vector3::unit_y(); // upward normal
        let eta_ratio = 1.0 / 1.33; // Air (n=1.0) to water (n=1.33)

        let refracted = incident.refract(&normal, eta_ratio);
        assert!(refracted.is_some(), "Should not experience TIR at normal incidence");
        
        let refracted_vec = refracted.unwrap();
        // Refracted vector should remain downward without horizontal component
        assert!(approx_eq(refracted_vec.x, 0.0, epsilon));
        assert!(approx_eq(refracted_vec.z, 0.0, epsilon));
        assert!(refracted_vec.y < 0.0, "Refracted vector must point downward");
        assert!(approx_eq(refracted_vec.magnitude(), 1.0, epsilon), "Refracted vector must be normalized");

        // Known TIR scenario: From water to air at steep angle
        let steep_incident = Vector3::new(0.8, 0.6, 0.0).normalized();
        let eta_ratio_tir = 1.33; // water (1.33) to air (1.0)
        let tir_result = steep_incident.refract(&normal, eta_ratio_tir);
        assert!(tir_result.is_none(), "Should experience TIR for steep angle from denser medium");
    }
    
    #[test]
    fn test_barycentric_coordinates() {
        // Triangle in the xy plane
        let a = Vector3::zero();
        let b = Vector3::unit_x();
        let c = Vector3::unit_y();
        
        // Point at vertex a
        let p1 = Vector3::zero();
        let (u1, v1, w1) = p1.barycentric_coordinates(&a, &b, &c);
        assert!(approx_eq(u1, 1.0, EPSILON));
        assert!(approx_eq(v1, 0.0, EPSILON));
        assert!(approx_eq(w1, 0.0, EPSILON));
        
        // Point at center of triangle
        let p2 = Vector3::new(1.0/3.0, 1.0/3.0, 0.0);
        let (u2, v2, w2) = p2.barycentric_coordinates(&a, &b, &c);
        assert!(approx_eq(u2, 1.0/3.0, EPSILON));
        assert!(approx_eq(v2, 1.0/3.0, EPSILON));
        assert!(approx_eq(w2, 1.0/3.0, EPSILON));
        
        // Point outside triangle
        let p3 = Vector3::new(1.0, 1.0, 0.0);
        let (u3, v3, w3) = p3.barycentric_coordinates(&a, &b, &c);
        assert!(u3 < 0.0 || v3 < 0.0 || w3 < 0.0);
    }
    
    #[test]
    fn test_triangle_containment() {
        // Triangle in the xy plane
        let a = Vector3::zero();
        let b = Vector3::unit_x();
        let c = Vector3::unit_y();
        
        // Points inside
        let p1 = Vector3::new(0.1, 0.1, 0.0);
        let p2 = Vector3::new(0.25, 0.25, 0.0);
        
        assert!(p1.is_inside_triangle(&a, &b, &c));
        assert!(p2.is_inside_triangle(&a, &b, &c));
        
        // Points outside
        let p3 = Vector3::new(1.0, 1.0, 0.0);
        let p4 = Vector3::new(-0.1, 0.5, 0.0);
        
        assert!(!p3.is_inside_triangle(&a, &b, &c));
        assert!(!p4.is_inside_triangle(&a, &b, &c));
        
        // Point on edge
        let p5 = Vector3::new(0.5, 0.5, 0.0);
        assert!(p5.is_inside_triangle(&a, &b, &c));
    }
    
    #[test]
    fn test_closest_point_on_segment() {
        let start = Vector3::zero();
        let end = Vector3::new(10.0, 0.0, 0.0);
        
        // Point projecting onto segment
        let p1 = Vector3::new(5.0, 5.0, 0.0);
        let closest1 = p1.closest_point_on_segment(&start, &end);
        assert_eq!(closest1, Vector3::new(5.0, 0.0, 0.0));
        
        // Point before segment start
        let p2 = Vector3::new(-5.0, 1.0, 0.0);
        let closest2 = p2.closest_point_on_segment(&start, &end);
        assert_eq!(closest2, start);
        
        // Point after segment end
        let p3 = Vector3::new(15.0, 2.0, 0.0);
        let closest3 = p3.closest_point_on_segment(&start, &end);
        assert_eq!(closest3, end);
        
        // Point directly above segment
        let p4 = Vector3::new(7.5, 0.0, 5.0);
        let closest4 = p4.closest_point_on_segment(&start, &end);
        assert_eq!(closest4, Vector3::new(7.5, 0.0, 0.0));
    }
    
    #[test]
    fn test_are_collinear() {
        // Collinear points on x-axis
        let a = Vector3::zero();
        let b = Vector3::new(5.0, 0.0, 0.0);
        let c = Vector3::new(10.0, 0.0, 0.0);
        assert!(Vector3::are_collinear(&a, &b, &c));
        
        // Non-collinear points
        let d = Vector3::new(0.0, 5.0, 0.0);
        assert!(!Vector3::are_collinear(&a, &b, &d));
        
        // Collinear but not on an axis
        let e = Vector3::new(1.0, 1.0, 1.0);
        let f = Vector3::new(2.0, 2.0, 2.0);
        let g = Vector3::new(3.0, 3.0, 3.0);
        assert!(Vector3::are_collinear(&e, &f, &g));
    }
    
    #[test]
    fn test_plane_operations() {
        let point = Vector3::new(0.0, 0.0, 0.0);
        let normal = Vector3::unit_z();
        
        // Project onto plane
        let v1 = Vector3::new(1.0, 2.0, 3.0);
        let projected = v1.project_onto_plane(&normal);
        assert_eq!(projected, Vector3::new(1.0, 2.0, 0.0));
        assert!(approx_eq(projected.dot(&normal), 0.0, EPSILON));
        
        // Distance to plane
        let v2 = Vector3::new(5.0, 5.0, 10.0);
        assert_eq!(v2.distance_to_plane(&point, &normal), 10.0);
        
        // Reflect across plane
        let v3 = Vector3::new(1.0, 1.0, 5.0);
        let reflected = v3.reflect_plane(&point, &normal);
        assert_eq!(reflected, Vector3::new(1.0, 1.0, -5.0));
    }
    
    #[test]
    fn test_static_collection_methods() {
        let vectors = vec![
            Vector3::new(1.0, 2.0, 3.0),
            Vector3::new(4.0, 5.0, 6.0),
            Vector3::new(7.0, 8.0, 9.0)
        ];
        
        // Test mean/centroid
        let mean = Vector3::mean(&vectors).unwrap();
        let expected_mean = Vector3::new(4.0, 5.0, 6.0);
        assert_eq!(mean, expected_mean);
        
        // Test variance
        let variance = Vector3::variance(&vectors, Some(mean)).unwrap();
        let expected_variance = Vector3::new(6.0, 6.0, 6.0);
        assert_eq!(variance, expected_variance);
        
        // Test min/max magnitude
        let min_mag = Vector3::min_magnitude(&vectors).unwrap();
        assert_eq!(min_mag, &vectors[0]);
        
        let max_mag = Vector3::max_magnitude(&vectors).unwrap();
        assert_eq!(max_mag, &vectors[2]);
        
        // Test bounding box
        let (min, max) = Vector3::bounding_box(&vectors).unwrap();
        assert_eq!(min, Vector3::new(1.0, 2.0, 3.0));
        assert_eq!(max, Vector3::new(7.0, 8.0, 9.0));
    }
    
    #[test]
    fn test_geometric_calculations() {
        // Triangle vertices
        let a = Vector3::zero();
        let b = Vector3::new(3.0, 0.0, 0.0);
        let c = Vector3::new(0.0, 4.0, 0.0);
        
        // Test triangle centroid
        let centroid = Vector3::triangle_centroid(&a, &b, &c);
        assert_eq!(centroid, Vector3::new(1.0, 4.0/3.0, 0.0));
        
        // Test triangle area (3-4-5 triangle)
        let area = Vector3::triangle_area(&a, &b, &c);
        assert_eq!(area, 6.0);
        
        // Test tetrahedron volume
        let d = Vector3::new(0.0, 0.0, 12.0);
        let volume = Vector3::tetrahedron_volume(&a, &b, &c, &d);
        assert_eq!(volume, 24.0); // 1/3 * base area * height
    }
    
    #[test]
    fn test_rotate_around_axis() {
        // Rotate (1,0,0) 90 degrees around z-axis should give (0,1,0)
        let v = Vector3::unit_x();
        let axis = Vector3::unit_z();
        let angle = std::f64::consts::FRAC_PI_2;
        
        let rotated = v.rotate_around_axis(&axis, angle);
        assert!(vec_approx_eq(&rotated, &Vector3::unit_y(), 1e-5));
        
        // Rotate 180 degrees
        let rotated2 = v.rotate_around_axis(&axis, std::f64::consts::PI);
        assert!(vec_approx_eq(&rotated2, &(-v), 1e-5));
        
        // Rotate 360 degrees (back to original)
        let rotated3 = v.rotate_around_axis(&axis, 2.0 * std::f64::consts::PI);
        assert!(vec_approx_eq(&rotated3, &v, 1e-5));
        
        // Rotation around arbitrary axis
        let v2 = Vector3::new(1.0, 2.0, 3.0);
        let axis2 = Vector3::new(1.0, 1.0, 1.0).normalized();
        
        // Rotation by 2π should return to original
        let full_rotation = v2.rotate_around_axis(&axis2, 2.0 * std::f64::consts::PI);
        assert!(vec_approx_eq(&full_rotation, &v2, 1e-5));
        
        // Properties of rotation around axis:
        // 1. Length is preserved
        let half_rotation = v2.rotate_around_axis(&axis2, std::f64::consts::PI);
        assert!(approx_eq(half_rotation.magnitude(), v2.magnitude(), 1e-5));
        
        // 2. The component parallel to axis should be unchanged
        let parallel_component = axis2.scale(v2.dot(&axis2));
        let parallel_component_rotated = axis2.scale(half_rotation.dot(&axis2));
        assert!(vec_approx_eq(&parallel_component, &parallel_component_rotated, 1e-5));
    }
}
